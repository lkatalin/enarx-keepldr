// SPDX-License-Identifier: Apache-2.0

// Credit to: https://github.com/fortanix/rust-sgx/tree/master/aesm-client
// for examples of AESM Requests.

use colour::*;

use crate::protobuf::aesm_proto::{
    Request, Request_GetQuoteRequest, Request_InitQuoteRequest, Response,
    Response_GetQuoteResponse, Response_InitQuoteResponse,
};
use crate::syscall::{SGX_DUMMY_QUOTE, SGX_DUMMY_TI, SGX_QUOTE_SIZE, SGX_TI_SIZE};

use std::io::{Error, ErrorKind, Read, Write};
use std::mem::size_of;
use std::os::unix::net::UnixStream;
use std::slice::{from_raw_parts, from_raw_parts_mut};

use byteorder::{NativeEndian, ReadBytesExt, WriteBytesExt};
use protobuf::{Message, ProtobufResult};

const AESM_SOCKET: &str = "/var/run/aesmd/aesm.socket";

/// Fills the Target Info of the QE into the output buffer specified and
/// returns the number of bytes written.
fn get_ti(out_buf: &mut [u8]) -> Result<usize, std::io::Error> {
    assert_eq!(out_buf.len(), SGX_TI_SIZE, "Invalid size of output buffer");

    // If unable to connect to the AESM daemon, return dummy value
    let mut stream = match UnixStream::connect(AESM_SOCKET) {
        Ok(s) => s,
        Err(_) => {
            out_buf.copy_from_slice(&SGX_DUMMY_TI);
            return Ok(SGX_TI_SIZE);
        }
    };

    cyan_ln!("HOST: received request for target info from shim\n");

    // Set an Init Quote Request
    let mut req = Request::new();
    let mut msg = Request_InitQuoteRequest::new();
    msg.set_timeout(1_000_000);
    req.set_initQuoteReq(msg);

    // Set up Writer
    let mut buf_wrtr = vec![0u8; size_of::<u32>()];
    match req.write_to_writer(&mut buf_wrtr) {
        Ok(_) => {}
        Err(e) => eprintln!("Error getting TargetInfo: {:#?}", e),
    }

    let req_len = (buf_wrtr.len() - size_of::<u32>()) as u32;
    (&mut buf_wrtr[0..size_of::<u32>()]).write_u32::<NativeEndian>(req_len)?;

    cyan_ln!("HOST: sending initQuoteRequest to AESM daemon\n");

    // Send Request to AESM daemon
    stream.write_all(&buf_wrtr)?;
    stream.flush()?;

    // Receive Response
    let res_len = stream.read_u32::<NativeEndian>()?;
    let mut res_bytes = vec![0; res_len as usize];
    stream.read_exact(&mut res_bytes)?;

    // Parse Response and extract TargetInfo
    let pb_msg: ProtobufResult<Response> = protobuf::parse_from_bytes(&res_bytes);
    let res: Response_InitQuoteResponse = pb_msg.unwrap().take_initQuoteRes();
    let ti = res.get_targetInfo();

    cyan_ln!("HOST: received target info from AESM daemon:\n\n");
    green_ln!("{:?}\n\n", ti);

    assert_eq!(
        ti.len(),
        out_buf.len(),
        "Unable to copy TargetInfo to buffer"
    );

    cyan_ln!("HOST: sending target info back to shim\n");
    out_buf.copy_from_slice(ti);
    Ok(ti.len())
}

/// Fills the Quote obtained from the AESMD for the Report specified into
/// the output buffer specified and returns the number of bytes written.
fn get_quote(report: &[u8], out_buf: &mut [u8]) -> Result<usize, std::io::Error> {
    assert_eq!(
        out_buf.len(),
        SGX_QUOTE_SIZE,
        "Invalid size of output buffer"
    );

    // If unable to connect to the AESM daemon, return dummy value
    let mut stream = match UnixStream::connect(AESM_SOCKET) {
        Ok(s) => s,
        Err(_) => {
            out_buf.copy_from_slice(&SGX_DUMMY_QUOTE);
            return Ok(SGX_QUOTE_SIZE);
        }
    };

    cyan_ln!("HOST: received request for quote info from shim\n");

    // Set a Get Quote Request
    let mut req = Request::new();
    let mut msg = Request_GetQuoteRequest::new();
    msg.set_report(report[0..432].to_vec());
    msg.set_quote_type(0); // TODO: Fix this value
    msg.set_spid([0u8; 16].to_vec()); // TODO: Fix this value
    msg.set_buf_size(1244); // TODO: FIx this value
    msg.set_timeout(1_000_000);
    req.set_getQuoteReq(msg);

    // Set up Writer
    let mut buf_wrtr = vec![0u8; size_of::<u32>()];
    match req.write_to_writer(&mut buf_wrtr) {
        Ok(_) => {}
        Err(e) => eprintln!("Error getting Quote: {:#?}", e),
    }
    let req_len = (buf_wrtr.len() - size_of::<u32>()) as u32;
    (&mut buf_wrtr[0..size_of::<u32>()]).write_u32::<NativeEndian>(req_len)?;

    cyan_ln!("HOST: sending getQuoteRequest to AESM daemon\n");

    // Send Request to AESM daemon
    stream.write_all(&buf_wrtr)?;
    stream.flush()?;

    // Receive Response
    let res_len = stream.read_u32::<NativeEndian>()?;
    let mut res_bytes = vec![0; res_len as usize];
    stream.read_exact(&mut res_bytes)?;

    // Parse Response and extract Quote
    let pb_msg: ProtobufResult<Response> = protobuf::parse_from_bytes(&res_bytes);
    let res: Response_GetQuoteResponse = pb_msg.unwrap().take_getQuoteRes();
    if res.get_errorCode() != 0 {
        eprintln!("Quote error code: {:?}", res.get_errorCode());
        return Err(Error::new(ErrorKind::InvalidData, "Error found in Quote"));
    }
    let quote = res.get_quote();
    if quote.is_empty() {
        return Err(Error::new(ErrorKind::InvalidData, "No data in Quote"));
    }

    cyan_ln!("HOST: received quote from AESM daemon:\n\n");
    green_ln!("{:?}\n\n", quote);

    assert_eq!(quote.len(), out_buf.len(), "Unable to copy Quote to buffer");
    out_buf.copy_from_slice(&quote);

    cyan_ln!("HOST: sending quote back to shim\n");

    Ok(quote.len())
}

/// Returns the number of bytes written to the output buffer. Depending on
/// whether the specified nonce is NULL, the output buffer will be filled with the
/// Target Info for the QE, or a Quote verifying a Report.
pub fn get_attestation(
    nonce: usize,
    _nonce_len: usize,
    buf: usize,
    buf_len: usize,
) -> Result<usize, Error> {
    let out_buf: &mut [u8] = unsafe { from_raw_parts_mut(buf as *mut u8, buf_len) };

    if nonce == 0 {
        Ok(get_ti(out_buf)?)
    } else {
        let report: &[u8] = unsafe { from_raw_parts(nonce as *const u8, _nonce_len) };
        Ok(get_quote(report, out_buf)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These values were generated by the QE in its TargetInfo.
    const EXPECTED_MRENCLAVE: [u8; 32] = [
        0xb2, 0xc1, 0xfe, 0x35, 0x7d, 0x7b, 0x10, 0x20, 0x54, 0x4f, 0xac, 0x33, 0x64, 0xc3, 0xf9,
        0xb8, 0x98, 0xc1, 0x75, 0x8d, 0xb4, 0x1, 0x1e, 0x9d, 0x65, 0x2e, 0x40, 0xec, 0xd1, 0x86,
        0x14, 0xbc,
    ];

    const SAMPLE_REPORT: [u8; 512] = [
        3, 9, 255, 255, 2, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 3, 0,
        0, 0, 0, 0, 0, 0, 22, 58, 88, 16, 125, 53, 233, 100, 17, 24, 200, 65, 26, 64, 74, 60, 66,
        222, 31, 118, 51, 69, 13, 209, 195, 223, 173, 140, 243, 230, 253, 139, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 177, 61, 135,
        106, 93, 83, 83, 127, 211, 215, 39, 124, 55, 194, 56, 135, 20, 122, 50, 245, 219, 208, 129,
        97, 51, 211, 47, 101, 75, 245, 153, 123, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 223, 31,
        156, 246, 241, 143, 199, 153, 178, 215, 41, 71, 144, 22, 86, 106, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 50, 201, 146, 54, 60, 3, 200, 185, 0, 187, 66, 32, 117, 71, 150,
        242, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    #[test]
    fn req_ti() {
        let output = [1u8; SGX_TI_SIZE];
        assert_eq!(
            get_attestation(0, 0, output.as_ptr() as usize, output.len()).unwrap(),
            SGX_TI_SIZE
        );
        assert!(output[0..32].eq(&EXPECTED_MRENCLAVE) || output.eq(&SGX_DUMMY_TI));
    }

    #[test]
    fn req_quote() {
        let output = [1u8; SGX_QUOTE_SIZE];
        assert_eq!(
            get_attestation(
                SAMPLE_REPORT.as_ptr() as usize,
                SAMPLE_REPORT.len(),
                output.as_ptr() as usize,
                output.len()
            )
            .unwrap(),
            SGX_QUOTE_SIZE
        );
    }
}
