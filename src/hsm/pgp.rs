use crate::args::{HsmAccess, HsmPin};
use crate::errors::*;
use std::fs;
use std::io::Write;
use talktosc::apdus;
use talktosc::apdus::APDU;
use talktosc::response::Response;
use termcolor::{BufferWriter, ColorChoice, WriteColor};
use termcolor::{Color, ColorSpec};

pub struct Card {
    card: pcsc::Card,
}

impl Card {
    pub fn connect() -> Result<Card> {
        let card = talktosc::create_connection().context("Failed to select smart card")?;
        Ok(Card { card })
    }

    pub fn send(&self, msg: APDU) -> Result<Response> {
        let resp = talktosc::send_and_parse(&self.card, msg)
            .context("Failed to communicate with smart card")?;
        if !resp.is_okay() {
            bail!("Operation failed: {:?}", resp);
        }
        Ok(resp)
    }

    pub fn verify_pw1_signing(&self, pin: Vec<u8>) -> Result<()> {
        let verify_pin = apdus::create_apdu_verify_pw1_for_sign(pin);
        let resp = self.send(verify_pin).context("Pin verification failed")?;
        debug!("Verified pw1 pin is valid for signing: {:?}", resp);
        Ok(())
    }

    pub fn select_openpgp(&self) -> Result<()> {
        let select_openpgp = apdus::create_apdu_select_openpgp();
        let resp = self
            .send(select_openpgp)
            .context("Failed to select openpgp on smartcard")?;
        debug!("Selected openpgp on smart card: {:?}", resp);
        Ok(())
    }

    pub fn disconnect(self) -> Result<()> {
        self.card
            .disconnect(pcsc::Disposition::LeaveCard)
            .map_err(|(_card, err)| anyhow!("Failed to disconnect from card: {:#}", err))
    }
}

pub fn read_pin(args: &HsmPin) -> Result<Option<Vec<u8>>> {
    if let Some(pin) = &args.value {
        Ok(Some(pin.as_bytes().to_vec()))
    } else if let Some(path) = &args.file {
        let mut buf = fs::read_to_string(path)
            .with_context(|| anyhow!("Failed to read pin from file: {:?}", path))?;
        buf.truncate(buf.trim_end().len());
        Ok(Some(buf.into_bytes()))
    } else {
        Ok(None)
    }
}

#[derive(Debug)]
pub enum Status {
    Ok,
    Error(Error),
    Other(String),
}

pub fn write_info(label: &str, status: Status) -> Result<()> {
    if !log::log_enabled!(log::Level::Info) {
        return Ok(());
    }
    let stdout = BufferWriter::stdout(ColorChoice::Auto);

    let mut buffer = stdout.buffer();
    write!(buffer, "{:50}", label)?;
    match status {
        Status::Ok => {
            buffer.set_color(ColorSpec::new().set_fg(Some(Color::Green)).set_bold(true))?;
            writeln!(buffer, "OK")?;
            buffer.reset()?;
        }
        Status::Error(err) => {
            buffer.set_color(ColorSpec::new().set_fg(Some(Color::Red)).set_bold(true))?;
            write!(buffer, "ERR")?;
            buffer.reset()?;
            writeln!(buffer, " {:#}", err)?;
        }
        Status::Other(text) => {
            buffer.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)).set_bold(true))?;
            writeln!(buffer, "{}", text)?;
            buffer.reset()?;
        }
    }
    stdout.print(&buffer)?;

    Ok(())
}

pub fn access(args: &HsmAccess) -> Result<()> {
    let card = Card::connect()?;

    write_info("Detected smart card", Status::Ok)?;
    card.select_openpgp()?;
    write_info("Selected openpgp key", Status::Ok)?;

    let pin = read_pin(&args.pin)?;
    write_info(
        "Hardware signing pw1 pin is valid",
        if let Some(pin) = pin {
            if let Err(err) = card.verify_pw1_signing(pin) {
                // Only log the warning if we're not going to print it anyways
                if !log::log_enabled!(log::Level::Info) {
                    warn!("{:#}", err);
                }

                Status::Error(err)
            } else {
                Status::Ok
            }
        } else {
            Status::Other("-".to_string())
        },
    )?;

    card.disconnect()?;

    Ok(())
}
