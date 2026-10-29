//! A loaded, generically named incompatible instrumentation ABI marker.
//! It installs no Hook and must be rejected without injecting a second base.
#[no_mangle]
pub extern "C" fn hh_agent_abi_version()->u32{0x0002_0000}
