// SPDX-License-Identifier: Apache-2.0

// Credit to: https://github.com/fortanix/rust-sgx/tree/master/aesm-client
// for examples of AESM Requests.

use crate::protobuf::aesm_proto::{
    Request, Request_SelectAttKeyIDRequest, Request_GetQuoteExRequest, Request_InitQuoteExRequest, Response, Response_SelectAttKeyIDResponse, Response_GetQuoteExResponse, Response_InitQuoteExResponse,
};
use crate::syscall::{SGX_DUMMY_QUOTE, SGX_DUMMY_TI, SGX_QUOTE_SIZE, SGX_TI_SIZE};

use std::io::{Error, ErrorKind, Read, Write};
use std::mem::size_of;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::slice::{from_raw_parts, from_raw_parts_mut};
use std::vec::Vec;

use protobuf::Message;

const AESM_SOCKET: &str = "/var/run/aesmd/aesm.socket";

fn get_ak_id(out_buf: &mut [u8]) -> Result<Vec<u8>, Error> {

    // If unable to connect to the AESM daemon, return dummy value
    let mut stream = match UnixStream::connect(AESM_SOCKET) {
        Ok(s) => s,
        Err(_) => {
            out_buf.copy_from_slice(&SGX_DUMMY_TI);
            return Ok(Vec::new());
        }
    };

    // Select an Attestation Key
    let mut req = Request::new();
    let mut msg = Request_SelectAttKeyIDRequest::new();
    msg.set_timeout(1_000_000);
    req.set_selectAttKeyIDReq(msg);
    
    // Set up Writer
    let mut buf_wrtr = vec![0u8; size_of::<u32>()];
    match req.write_to_writer(&mut buf_wrtr) {
        Ok(_) => {}
        Err(e) => {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Invalid Select Att Key ID Request: {:#?}", e),
            ));
        }
    }

    let req_len = (buf_wrtr.len() - size_of::<u32>()) as u32;
    (&mut buf_wrtr[0..size_of::<u32>()]).copy_from_slice(&req_len.to_le_bytes());

    // Send Request to AESM daemon
    stream.write_all(&buf_wrtr)?;
    stream.flush()?;

    // Receive Response
    let mut res_len_bytes = [0u8; 4];
    stream.read_exact(&mut res_len_bytes)?;
    let res_len = u32::from_le_bytes(res_len_bytes);

    let mut res_bytes = vec![0; res_len as usize];
    stream.read_exact(&mut res_bytes)?;

    // Parse Response and extract AttKeyID
    let mut pb_msg: Response = protobuf::parse_from_bytes(&res_bytes)?;
    let mut res: Response_SelectAttKeyIDResponse = pb_msg.take_selectAttKeyIDRes();

    // The error code is zero here, but that's not supposed to be one of the error codes?
    if res.has_errorCode() && (res.get_errorCode() != 1u32) && (res.get_errorCode() != 0u32) {
        panic!("Received error code {:?} in Select Att Key ID Response", res.get_errorCode());
    }

    let attkeyid = res.take_selected_att_key_id();

    assert!(attkeyid != &[]);
    Ok(attkeyid)

//    stream.flush()?;

//    stream.shutdown(Shutdown::Both);

//    assert_eq!(0, 7);

}

/// Fills the Target Info of the QE into the output buffer specified and
/// returns the number of bytes written.
fn get_ti(out_buf: &mut [u8], akid: Vec<u8>) -> Result<usize, Error> {
    assert_eq!(out_buf.len(), SGX_TI_SIZE, "Invalid size of output buffer");

    // If unable to connect to the AESM daemon, return dummy value
    let mut stream = match UnixStream::connect(AESM_SOCKET) {
        Ok(s) => s,
        Err(_) => {
            out_buf.copy_from_slice(&SGX_DUMMY_TI);
            return Ok(SGX_TI_SIZE);
        }
    };

    // Set an Init Quote Ex Request
    let mut req = Request::new();
    let mut msg = Request_InitQuoteExRequest::new();
    msg.set_timeout(1_000_000);
    msg.set_b_pub_key_id(false);
    msg.set_att_key_id(akid);
    req.set_initQuoteExReq(msg);

    // Set up Writer
    let mut buf_wrtr = vec![0u8; size_of::<u32>()];
    match req.write_to_writer(&mut buf_wrtr) {
        Ok(_) => {}
        Err(e) => {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Invalid Init Quote Ex Request: {:#?}", e),
            ));
        }
    }

    let req_len = (buf_wrtr.len() - size_of::<u32>()) as u32;
    (&mut buf_wrtr[0..size_of::<u32>()]).copy_from_slice(&req_len.to_le_bytes());

//    assert_eq!(0, 8);
    
    // Send Request to AESM daemon
    stream.write_all(&buf_wrtr)?;
    stream.flush()?;

    // Receive Response
    let mut res_len_bytes = [0u8; 4];
    stream.read_exact(&mut res_len_bytes)?;
    let res_len = u32::from_le_bytes(res_len_bytes);

    let mut res_bytes = vec![0; res_len as usize];
    stream.read_exact(&mut res_bytes)?;

    // Parse Response and extract TargetInfo
    let mut pb_msg: Response = protobuf::parse_from_bytes(&res_bytes)?;
    let res: Response_InitQuoteExResponse = pb_msg.take_initQuoteExRes();

    if res.has_errorCode() && (res.get_errorCode() != 1u32 && res.get_errorCode() != 0u32) {
        panic!("Init Quote Ex Reponse has error code: {}", res.get_errorCode());
    }

//    assert_eq!(res.get_errorCode(), 1u32);

    let ti = res.get_target_info();

    assert_eq!(
        ti.len(),
        out_buf.len(),
        "Unable to copy TargetInfo to buffer"
    );

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

    // Get Quote Size

    // Set a Get Quote Request
    let mut req = Request::new();
    let mut msg = Request_GetQuoteExRequest::new();
    msg.set_report(report[0..432].to_vec());
    msg.set_buf_size(1277);
    msg.set_timeout(1_000_000);
    req.set_getQuoteExReq(msg);

    // Set up Writer
    let mut buf_wrtr = vec![0u8; size_of::<u32>()];
    match req.write_to_writer(&mut buf_wrtr) {
        Ok(_) => {}
        Err(e) => {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Invalid Get Quote Ex Request: {:#?}", e),
            ));
        }
    }

    let req_len = (buf_wrtr.len() - size_of::<u32>()) as u32;
    (&mut buf_wrtr[0..size_of::<u32>()]).copy_from_slice(&req_len.to_le_bytes());

    // Send Request to AESM daemon
    stream.write_all(&buf_wrtr)?;
    stream.flush()?;

    // Receive Response
    let mut res_len_bytes = [0u8; 4];
    stream.read_exact(&mut res_len_bytes)?;
    let res_len = u32::from_le_bytes(res_len_bytes);

    let mut res_bytes = vec![0; res_len as usize];
    stream.read_exact(&mut res_bytes)?;

    // Parse Response and extract Quote
    let mut pb_msg: Response = protobuf::parse_from_bytes(&res_bytes)?;
    let res: Response_GetQuoteExResponse = pb_msg.take_getQuoteExRes();
    if res.get_errorCode() != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "Error found in Quote. Error code: {:?}",
                res.get_errorCode()
            ),
        ));
    }
    let quote = res.get_quote();
    if quote.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Error: No data in Quote",
        ));
    }

    assert_eq!(quote.len(), out_buf.len(), "Unable to copy Quote to buffer");
    out_buf.copy_from_slice(&quote);
    println!("quote len: {:?}", quote.len());
    println!("quote:\n {:?}", quote);
    std::process::exit(0);

    Ok(quote.len())
}

/// Returns the number of bytes written to the output buffer. Depending on
/// whether the specified nonce is NULL, the output buffer will be filled with the
/// Target Info for the QE, or a Quote verifying a Report.
pub fn get_attestation(
    nonce: usize,
    nonce_len: usize,
    buf: usize,
    buf_len: usize,
) -> Result<usize, Error> {
    let out_buf: &mut [u8] = unsafe { from_raw_parts_mut(buf as *mut u8, buf_len) };

    if nonce == 0 {
        let akid = get_ak_id(out_buf).unwrap();
        assert!(!akid.is_empty());
        get_ti(out_buf, akid)
    } else {
        let report: &[u8] = unsafe { from_raw_parts(nonce as *const u8, nonce_len) };
        get_quote(report, out_buf)
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
