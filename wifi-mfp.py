import argparse
import struct
from scapy.all import rdpcap, Dot11, Dot11Elt
from rich import print
from rich.console import Console
from rich.table import Table
from rich.syntax import Syntax

console = Console()

class CheckMFP:

    def __init__(self, debug=None):
        self.debug = debug
        self.unique_aps = set()  # Track unique BSSIDs (MAC addresses)

    def mfp_status_string(self, mfp_capable, mfp_required):
        """Return a colored MFP status string."""
        if mfp_required:
            return "[bold green]MFP Required[/bold green]"
        elif mfp_capable:
            return "[bold yellow]MFP Supported[/bold yellow]"
        else:
            return "[red]MFP Not Enabled[/red]"

    def parse_rsn_capabilities(self, rsn_ie):
        """Extract and interpret the RSN Capabilities from the RSN IE."""
        rsn_info = rsn_ie.info
        index = 2  # Skip version
        group_cipher_suite = rsn_info[index:index+4]  # Group Cipher Suite
        index += 4
        pairwise_count = struct.unpack("<H", rsn_info[index:index+2])[0]
        index += 2 + (4 * pairwise_count)
        akm_count = struct.unpack("<H", rsn_info[index:index+2])[0]
        akm_suites = rsn_info[index + 2:index + 2 + 4 * akm_count]
        index += 2 + (4 * akm_count)
        rsn_capabilities = struct.unpack("<H", rsn_info[index:index+2])[0]
        rsn_capabilities_binary = format(rsn_capabilities, '016b')
        mfp_capable = bool(int(rsn_capabilities_binary[8]))
        mfp_required = bool(int(rsn_capabilities_binary[9]))

        return mfp_capable, mfp_required, group_cipher_suite, akm_suites

    def extract_ssid_rsn_channel(self, packet):
        """Extract SSID, RSN Information Elements (IEs), and channel from the packet."""
        ssid = None
        rsn_ie = None
        channel = None
        elt = packet.getlayer(Dot11Elt)

        while elt is not None:
            if elt.ID == 0:  # SSID element
                ssid = elt.info.decode('utf-8', errors='ignore').strip()
            elif elt.ID == 48:  # RSN Information Element (WPA2/WPA3)
                rsn_ie = elt
            elif elt.ID == 3:  # DS Parameter Set (Channel number)
                channel = elt.info[0]  # Extract the first byte which holds the channel number
            elt = elt.payload.getlayer(Dot11Elt)

        return ssid, rsn_ie, channel

    def identify_encryption(self, group_cipher_suite):
        """Identify encryption type (CCMP/TKIP/WEP) based on the group cipher suite."""
        cipher_suites = {
            b"\x00\x0f\xac\x02": "TKIP",
            b"\x00\x0f\xac\x04": "CCMP",
            b"\x00\x0f\xac\x01": "WEP"
        }
        return cipher_suites.get(group_cipher_suite, "Unknown")

    def identify_wpa_version(self, akm_suites):
        """Identify WPA version based on AKM suite."""
        wpa3_akm = b"\x00\x0f\xac\x08"
        if wpa3_akm in akm_suites:
            return "WPA3"
        return "WPA2"

    def identify_akm(self, akm_suites):
        """Identify AKM (Authentication Key Management) Suite (PSK, EAP, etc.)."""
        akm_types = {
            b"\x00\x0f\xac\x02": "PSK",
            b"\x00\x0f\xac\x01": "EAP",
            b"\x00\x0f\xac\x08": "SAE"
        }
        return akm_types.get(akm_suites[:4], "Unknown")

    def print_packet(self, packet):
        """Print the entire packet with syntax highlighting."""
        packet_str = packet.show(dump=True)  # Get packet as string
        syntax = Syntax(packet_str, "python", theme="monokai", line_numbers=True)
        console.print(syntax)

    def print_frame_flags(self, packet, ssid, channel):
        """Print the frame control flags."""
        flags = int(packet.FCfield)
        flags_binary = f"{flags:08b}"  # Convert flags to binary format
        flag_output = f"\n[bold green]Frame Flags for SSID: {ssid} (Channel {channel})[/bold green]\n"
        flag_output += f"[bold green]Flags[/bold green]: 0x{flags:02x} ({flags_binary})\n"
        flag_output += f".... ..{flags_binary[7]} = To DS status\n"
        flag_output += f".... .{flags_binary[6]} = More Fragments\n"
        flag_output += f".... {flags_binary[5]} = Retry\n"
        flag_output += f"... {flags_binary[4]} = PWR MGT\n"
        flag_output += f".. {flags_binary[3]} = More Data\n"
        if flags_binary[2] == '0':
            flag_output += f"[bold red]. {flags_binary[2]} = Protected flag: Data is not protected[/bold red]\n"
        else:
            flag_output += f"[bold green]. {flags_binary[2]} = Protected flag: Data is protected[/bold green]\n"
        flag_output += f"{flags_binary[1]} = HT/Order flag\n"
        return flag_output


    def check_mfp(self, pcap_file, print_full_packet, print_frames, target_ssid=None, target_channel=None):
        packets = rdpcap(pcap_file)
        table = Table(title="Wi-Fi Network Details")
        table.add_column("SSID", style="bold cyan")
        table.add_column("Encryption", style="bold magenta")
        table.add_column("WPA Version", style="bold yellow")
        table.add_column("AKM (PSK/EAP)", style="bold green")
        table.add_column("MFP Status", style="bold red")
        table.add_column("Channel", style="bold blue")

        combined_output = ""

        for packet in packets:
            if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 8:  # Beacon frames
                ssid, rsn_ie, channel = self.extract_ssid_rsn_channel(packet)
                bssid = packet.addr2  # Extract BSSID (MAC address)

                # Skip if SSID, RSN IE is missing or the BSSID has already been seen
                if ssid is None or rsn_ie is None or bssid in self.unique_aps:
                    continue

                # Filter based on the provided SSID and channel
                if target_ssid and ssid != target_ssid:
                    continue
                if target_channel and channel != target_channel:
                    continue

                self.unique_aps.add(bssid)  # Track unique BSSIDs

                mfp_capable, mfp_required, group_cipher_suite, akm_suites = self.parse_rsn_capabilities(rsn_ie)
                encryption_type = self.identify_encryption(group_cipher_suite)
                wpa_version = self.identify_wpa_version(akm_suites)
                akm_type = self.identify_akm(akm_suites)
                mfp_status = self.mfp_status_string(mfp_capable, mfp_required)

                table.add_row(ssid, encryption_type, wpa_version, akm_type, mfp_status, str(channel))

                if print_frames:
                    combined_output += self.print_frame_flags(packet, ssid, channel)
                if print_full_packet:
                    self.print_packet(packet)

        console.print(table)
        if combined_output:
            console.print(combined_output)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check MFP status in a PCAP file.")
    parser.add_argument("pcap_file", help="The PCAP file to analyze")
    parser.add_argument("-s", "--ssid", help="Specify an SSID to filter and print only that one")
    parser.add_argument("-c", "--channel", type=int, help="Specify a channel to filter and print only those SSIDs on the channel")
    parser.add_argument("-p", "--print-frames", action="store_true", help="Print frame flags for each SSID")
    parser.add_argument("-P", "--print-packet", action="store_true", help="Print the entire packet with syntax highlighting")
    parser.add_argument("-D", "--debug", action="store_true", help="Print debug statements for troubleshooting")
    args = parser.parse_args()

    run = CheckMFP(debug=args.debug)
    run.check_mfp(args.pcap_file, args.print_packet, args.print_frames, args.ssid, args.channel)