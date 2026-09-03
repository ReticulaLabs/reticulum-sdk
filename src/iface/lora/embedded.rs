//! Embedded (`embedded-hal`) SPI + GPIO backends for the LoRa interface.
//!
//! These let a LoRa radio (SX1262/SX1276/LR1121) be driven on a
//! microcontroller over an [`embedded_hal::spi::SpiDevice`] plus `embedded-hal`
//! GPIO pins, with no Linux `spidev` / `gpio-cdev` dependency.
//!
//! # Example
//!
//! ```rust,ignore
//! use std::sync::{Arc, Mutex};
//! use reticulum_sdk::iface::lora::embedded::{
//!     EmbeddedInputPin, EmbeddedLoRaHw, EmbeddedOutputPin, EmbeddedSpi,
//! };
//! use reticulum_sdk::iface::lora::LoRaConfig;
//!
//! // `spi` is an embedded_hal::spi::SpiDevice, and the pins are
//! // embedded_hal digital pins from the board HAL.
//! let hw = Arc::new(EmbeddedLoRaHw::new(
//!     Arc::new(Mutex::new(spi)),
//!     Some(Arc::new(Mutex::new(busy_pin))),   // input
//!     Some(Arc::new(Mutex::new(reset_pin))),  // output
//!     Some(Arc::new(Mutex::new(dio1_pin))),   // input
//! ));
//! let config = LoRaConfig::new("", 868_000_000, 125_000.0, 14, 7, 5)
//!     .with_embedded_hw(hw);
//! ```

use std::sync::{Arc, Mutex};

use embedded_hal::digital::{InputPin, OutputPin};
use embedded_hal::spi::SpiDevice;

use super::{GpioPins, LoRaError, LoRaGpio, LoRaHwProvider, LoRaSpi};

/// An `embedded-hal` SPI device adapter implementing [`LoRaSpi`].
///
/// Wraps the device in an `Arc<Mutex<..>>` so the interface can re-open the
/// chipset (on reconnect) against the same bus.
pub struct EmbeddedSpi<DEV: 'static> {
    dev: Arc<Mutex<DEV>>,
}

impl<DEV: 'static> EmbeddedSpi<DEV> {
    pub fn new(dev: Arc<Mutex<DEV>>) -> Self {
        Self { dev }
    }
}

impl<DEV> LoRaSpi for EmbeddedSpi<DEV>
where
    DEV: SpiDevice<Error: core::fmt::Debug> + Send,
{
    fn xfer(&mut self, tx_buf: &[u8], rx_buf: &mut [u8]) -> Result<(), LoRaError> {
        self.dev
            .lock()
            .map_err(|_| LoRaError::Spi("embedded SPI lock poisoned".into()))?
            .transfer(rx_buf, tx_buf)
            .map_err(|e| LoRaError::Spi(format!("embedded SPI transfer failed: {e:?}")))
    }
}

/// An `embedded-hal` input pin (e.g. `busy` / `dio1`) implementing [`LoRaGpio`].
pub struct EmbeddedInputPin<P: 'static> {
    pin: Arc<Mutex<P>>,
}

impl<P: 'static> EmbeddedInputPin<P> {
    pub fn new(pin: Arc<Mutex<P>>) -> Self {
        Self { pin }
    }
}

impl<P> LoRaGpio for EmbeddedInputPin<P>
where
    P: InputPin<Error: core::fmt::Debug> + Send,
{
    fn get_value(&self) -> Result<bool, LoRaError> {
        let mut pin = self
            .pin
            .lock()
            .map_err(|_| LoRaError::Gpio("embedded input pin lock poisoned".into()))?;
        pin.is_high().map_err(|e| LoRaError::Gpio(format!("read failed: {e:?}")))
    }

    fn set_value(&self, _value: bool) -> Result<(), LoRaError> {
        Err(LoRaError::Gpio("pin is configured as an input".into()))
    }
}

/// An `embedded-hal` output pin (e.g. `reset`) implementing [`LoRaGpio`].
pub struct EmbeddedOutputPin<P: 'static> {
    pin: Arc<Mutex<P>>,
}

impl<P: 'static> EmbeddedOutputPin<P> {
    pub fn new(pin: Arc<Mutex<P>>) -> Self {
        Self { pin }
    }
}

impl<P> LoRaGpio for EmbeddedOutputPin<P>
where
    P: OutputPin<Error: core::fmt::Debug> + Send,
{
    fn get_value(&self) -> Result<bool, LoRaError> {
        Err(LoRaError::Gpio("pin is configured as an output".into()))
    }

    fn set_value(&self, value: bool) -> Result<(), LoRaError> {
        let mut pin = self
            .pin
            .lock()
            .map_err(|_| LoRaError::Gpio("embedded output pin lock poisoned".into()))?;
        if value {
            pin.set_high().map_err(|e| LoRaError::Gpio(format!("set_high failed: {e:?}")))
        } else {
            pin.set_low().map_err(|e| LoRaError::Gpio(format!("set_low failed: {e:?}")))
        }
    }
}

/// A [`LoRaHwProvider`] built from `embedded-hal` devices and pins.
///
/// Construct once per radio and pass to [`super::LoRaConfig::with_embedded_hw`].
pub struct EmbeddedLoRaHw<DEV: 'static, BUSY: 'static, RESET: 'static, DIO1: 'static> {
    spi: Arc<Mutex<DEV>>,
    busy: Option<Arc<Mutex<BUSY>>>,
    reset: Option<Arc<Mutex<RESET>>>,
    dio1: Option<Arc<Mutex<DIO1>>>,
}

impl<DEV: 'static, BUSY: 'static, RESET: 'static, DIO1: 'static> EmbeddedLoRaHw<DEV, BUSY, RESET, DIO1> {
    pub fn new(
        spi: Arc<Mutex<DEV>>,
        busy: Option<Arc<Mutex<BUSY>>>,
        reset: Option<Arc<Mutex<RESET>>>,
        dio1: Option<Arc<Mutex<DIO1>>>,
    ) -> Self {
        Self { spi, busy, reset, dio1 }
    }
}

impl<DEV: 'static, BUSY: 'static, RESET: 'static, DIO1: 'static> LoRaHwProvider for EmbeddedLoRaHw<DEV, BUSY, RESET, DIO1>
where
    DEV: SpiDevice<Error: core::fmt::Debug> + Send,
    BUSY: InputPin<Error: core::fmt::Debug> + Send,
    RESET: OutputPin<Error: core::fmt::Debug> + Send,
    DIO1: InputPin<Error: core::fmt::Debug> + Send,
{
    fn build(&self) -> Result<(Box<dyn LoRaSpi>, GpioPins), LoRaError> {
        Ok((
            Box::new(EmbeddedSpi::new(self.spi.clone())),
            GpioPins {
                busy: self.busy.as_ref().map(|p| Box::new(EmbeddedInputPin::new(p.clone())) as Box<dyn LoRaGpio>),
                reset: self.reset.as_ref().map(|p| Box::new(EmbeddedOutputPin::new(p.clone())) as Box<dyn LoRaGpio>),
                dio1: self.dio1.as_ref().map(|p| Box::new(EmbeddedInputPin::new(p.clone())) as Box<dyn LoRaGpio>),
            },
        ))
    }
}