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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1664.1");
  script_cve_id("CVE-2017-9343", "CVE-2017-9344", "CVE-2017-9345", "CVE-2017-9346", "CVE-2017-9347", "CVE-2017-9348", "CVE-2017-9349", "CVE-2017-9350", "CVE-2017-9351", "CVE-2017-9352", "CVE-2017-9353", "CVE-2017-9354");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:55 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-19 18:27:00 +0000 (Tue, 19 Mar 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1664-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1664-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171664-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the SUSE-SU-2017:1664-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The network analysis tool wireshark was updated to version 2.0.13 to fix the following issues:
* CVE-2017-9352: Bazaar dissector infinite loop (wnpa-sec-2017-22)
 (bsc#1042304)
* CVE-2017-9348: DOF dissector read overflow (wnpa-sec-2017-23)
 (bsc#1042303)
* CVE-2017-9351: DHCP dissector read overflow (wnpa-sec-2017-24)
 (bsc#1042302)
* CVE-2017-9346: SoulSeek dissector infinite loop (wnpa-sec-2017-25)
 (bsc#1042301)
* CVE-2017-9345: DNS dissector infinite loop (wnpa-sec-2017-26)
 (bsc#1042300)
* CVE-2017-9349: DICOM dissector infinite loop (wnpa-sec-2017-27)
 (bsc#1042305)
* CVE-2017-9350: openSAFETY dissector memory exh.. (wnpa-sec-2017-28)
 (bsc#1042299)
* CVE-2017-9344: BT L2CAP dissector divide by zero (wnpa-sec-2017-29)
 (bsc#1042298)
* CVE-2017-9343: MSNIP dissector crash (wnpa-sec-2017-30) (bsc#1042309)
* CVE-2017-9347: ROS dissector crash (wnpa-sec-2017-31) (bsc#1042308)
* CVE-2017-9354: RGMP dissector crash (wnpa-sec-2017-32) (bsc#1042307)
* CVE-2017-9353: wireshark: IPv6 dissector crash (wnpa-sec-2017-33)
 (bsc#1042306)");

  script_tag(name:"affected", value:"'wireshark' package(s) on SUSE Linux Enterprise Software Development Kit 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Debuginfo 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~2.0.13~39.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-gtk", rpm:"wireshark-gtk~2.0.13~39.1", rls:"SLES11.0SP4"))) {
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
