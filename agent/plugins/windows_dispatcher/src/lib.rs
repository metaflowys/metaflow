/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Enterprise Edition Feature: windows-dispatcher

use std::{
    slice::from_raw_parts_mut,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use ::pcap::{Active, Capture, Device};
use public::counter;
use public::error::{Error, Result};
use public::packet;

#[derive(Default)]
pub struct WinPcapCounter(AtomicU64);

impl counter::RefCountable for WinPcapCounter {
    fn get_counters(&self) -> Vec<counter::Counter> {
        vec![(
            "kernel_drops",
            counter::CounterType::Counted,
            counter::CounterValue::Unsigned(self.0.swap(0, Ordering::Relaxed)),
        )]
    }
}

pub struct WinPacket {
    captures: Vec<(Capture<Active>, isize, u64)>,
    cur_read_offset: usize,
    counter: Arc<WinPcapCounter>,
}

impl WinPacket {
    pub fn new(_: Vec<(&str, isize)>, _: usize, _: usize) -> Result<Self> {
        Ok(Self {
            captures: vec![],
            cur_read_offset: 0,
            counter: Arc::new(WinPcapCounter::default()),
        })
    }

    pub fn read(&mut self) -> Result<packet::Packet> {
        Ok(packet::Packet {
            timestamp: Default::default(),
            if_index: 0,
            capture_length: 0,
            data: &mut [],
        })
    }

    pub fn set_bpf(&mut self, _: &str) -> Result<()> {
        Ok(())
    }

    pub fn get_counter_handle(&self) -> Arc<dyn counter::RefCountable> {
        self.counter.clone()
    }
}
