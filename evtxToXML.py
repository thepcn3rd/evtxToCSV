#!/usr/bin/python3

# apt install python3-evtx
import Evtx.Evtx as evtx
import Evtx.Views as e_views

evtxFile='Logs/Microsoft-Windows-PowerShell%4Operational.evtx'

with evtx.Evtx(evtxFile) as log:
    for record in log.records():
        print(record.xml())
