# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1110.1");
  script_cve_id("CVE-2014-8767", "CVE-2014-8768", "CVE-2014-8769", "CVE-2015-0261", "CVE-2015-2153", "CVE-2015-2154", "CVE-2015-2155", "CVE-2015-3138", "CVE-2016-7922", "CVE-2016-7923", "CVE-2016-7924", "CVE-2016-7925", "CVE-2016-7926", "CVE-2016-7927", "CVE-2016-7928", "CVE-2016-7929", "CVE-2016-7930", "CVE-2016-7931", "CVE-2016-7932", "CVE-2016-7933", "CVE-2016-7934", "CVE-2016-7935", "CVE-2016-7936", "CVE-2016-7937", "CVE-2016-7938", "CVE-2016-7939", "CVE-2016-7940", "CVE-2016-7973", "CVE-2016-7974", "CVE-2016-7975", "CVE-2016-7983", "CVE-2016-7984", "CVE-2016-7985", "CVE-2016-7986", "CVE-2016-7992", "CVE-2016-7993", "CVE-2016-8574", "CVE-2016-8575", "CVE-2017-5202", "CVE-2017-5203", "CVE-2017-5204", "CVE-2017-5205", "CVE-2017-5341", "CVE-2017-5342", "CVE-2017-5482", "CVE-2017-5483", "CVE-2017-5484", "CVE-2017-5485", "CVE-2017-5486");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1110-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1110-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171110-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tcpdump, libpcap' package(s) announced via the SUSE-SU-2017:1110-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tcpdump to version 4.9.0 and libpcap to version 1.8.1 fixes the several issues.
These security issues were fixed in tcpdump:
- CVE-2016-7922: The AH parser in tcpdump had a buffer overflow in
 print-ah.c:ah_print() (bsc#1020940).
- CVE-2016-7923: The ARP parser in tcpdump had a buffer overflow in
 print-arp.c:arp_print() (bsc#1020940).
- CVE-2016-7924: The ATM parser in tcpdump had a buffer overflow in
 print-atm.c:oam_print() (bsc#1020940).
- CVE-2016-7925: The compressed SLIP parser in tcpdump had a buffer
 overflow in print-sl.c:sl_if_print() (bsc#1020940).
- CVE-2016-7926: The Ethernet parser in tcpdump had a buffer overflow in
 print-ether.c:ethertype_print() (bsc#1020940).
- CVE-2016-7927: The IEEE 802.11 parser in tcpdump had a buffer overflow
 in print-802_11.c:ieee802_11_radio_print() (bsc#1020940).
- CVE-2016-7928: The IPComp parser in tcpdump had a buffer overflow in
 print-ipcomp.c:ipcomp_print() (bsc#1020940).
- CVE-2016-7929: The Juniper PPPoE ATM parser in tcpdump had a buffer
 overflow in print-juniper.c:juniper_parse_header() (bsc#1020940).
- CVE-2016-7930: The LLC/SNAP parser in tcpdump had a buffer overflow in
 print-llc.c:llc_print() (bsc#1020940).
- CVE-2016-7931: The MPLS parser in tcpdump had a buffer overflow in
 print-mpls.c:mpls_print() (bsc#1020940).
- CVE-2016-7932: The PIM parser in tcpdump had a buffer overflow in
 print-pim.c:pimv2_check_checksum() (bsc#1020940).
- CVE-2016-7933: The PPP parser in tcpdump had a buffer overflow in
 print-ppp.c:ppp_hdlc_if_print() (bsc#1020940).
- CVE-2016-7934: The RTCP parser in tcpdump had a buffer overflow in
 print-udp.c:rtcp_print() (bsc#1020940).
- CVE-2016-7935: The RTP parser in tcpdump had a buffer overflow in
 print-udp.c:rtp_print() (bsc#1020940).
- CVE-2016-7936: The UDP parser in tcpdump had a buffer overflow in
 print-udp.c:udp_print() (bsc#1020940).
- CVE-2016-7937: The VAT parser in tcpdump had a buffer overflow in
 print-udp.c:vat_print() (bsc#1020940).
- CVE-2016-7938: The ZeroMQ parser in tcpdump had an integer overflow in
 print-zeromq.c:zmtp1_print_frame() (bsc#1020940).
- CVE-2016-7939: The GRE parser in tcpdump had a buffer overflow in
 print-gre.c, multiple functions (bsc#1020940).
- CVE-2016-7940: The STP parser in tcpdump had a buffer overflow in
 print-stp.c, multiple functions (bsc#1020940).
- CVE-2016-7973: The AppleTalk parser in tcpdump had a buffer overflow in
 print-atalk.c, multiple functions (bsc#1020940).
- CVE-2016-7974: The IP parser in tcpdump had a buffer overflow in
 print-ip.c, multiple functions (bsc#1020940).
- CVE-2016-7975: The TCP parser in tcpdump had a buffer overflow in
 print-tcp.c:tcp_print() (bsc#1020940).
- CVE-2016-7983: The BOOTP parser in tcpdump had a buffer overflow in
 print-bootp.c:bootp_print() (bsc#1020940).
- CVE-2016-7984: The TFTP parser in tcpdump had a buffer overflow in
 print-tftp.c:tftp_print() (bsc#1020940).
- ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'tcpdump, libpcap' package(s) on SUSE Linux Enterprise Workstation Extension 12-SP2, SUSE Linux Enterprise Workstation Extension 12-SP1, SUSE Linux Enterprise Software Development Kit 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP1, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Desktop 12-SP1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libpcap-debugsource", rpm:"libpcap-debugsource~1.8.1~9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcap1", rpm:"libpcap1~1.8.1~9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcap1-debuginfo", rpm:"libpcap1-debuginfo~1.8.1~9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tcpdump", rpm:"tcpdump~4.9.0~13.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tcpdump-debuginfo", rpm:"tcpdump-debuginfo~4.9.0~13.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tcpdump-debugsource", rpm:"tcpdump-debugsource~4.9.0~13.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libpcap-debugsource", rpm:"libpcap-debugsource~1.8.1~9.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcap1", rpm:"libpcap1~1.8.1~9.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcap1-debuginfo", rpm:"libpcap1-debuginfo~1.8.1~9.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tcpdump", rpm:"tcpdump~4.9.0~13.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tcpdump-debuginfo", rpm:"tcpdump-debuginfo~4.9.0~13.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tcpdump-debugsource", rpm:"tcpdump-debugsource~4.9.0~13.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
