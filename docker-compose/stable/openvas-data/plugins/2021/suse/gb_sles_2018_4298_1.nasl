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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.4298.1");
  script_cve_id("CVE-2018-19622", "CVE-2018-19623", "CVE-2018-19624", "CVE-2018-19625", "CVE-2018-19626", "CVE-2018-19627");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-20 01:15:00 +0000 (Fri, 20 Mar 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:4298-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:4298-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20184298-1/");
  script_xref(name:"URL", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.4.11.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the SUSE-SU-2018:4298-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for wireshark fixes the following issues:

Update to Wireshark 2.4.11 (bsc#1117740).

Security issues fixed:
CVE-2018-19625: The Wireshark dissection engine could crash
 (wnpa-sec-2018-51)

CVE-2018-19626: The DCOM dissector could crash (wnpa-sec-2018-52)

CVE-2018-19623: The LBMPDM dissector could crash (wnpa-sec-2018-53)

CVE-2018-19622: The MMSE dissector could go into an infinite loop
 (wnpa-sec-2018-54)

CVE-2018-19627: The IxVeriWave file parser could crash (wnpa-sec-2018-55)

CVE-2018-19624: The PVFS dissector could crash (wnpa-sec-2018-56)

Further bug fixes and updated protocol support as listed in:
[link moved to references]");

  script_tag(name:"affected", value:"'wireshark' package(s) on SUSE Linux Enterprise Software Development Kit 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Desktop 12-SP3.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libwireshark9", rpm:"libwireshark9~2.4.11~48.35.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark9-debuginfo", rpm:"libwireshark9-debuginfo~2.4.11~48.35.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap7", rpm:"libwiretap7~2.4.11~48.35.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap7-debuginfo", rpm:"libwiretap7-debuginfo~2.4.11~48.35.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwscodecs1", rpm:"libwscodecs1~2.4.11~48.35.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwscodecs1-debuginfo", rpm:"libwscodecs1-debuginfo~2.4.11~48.35.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil8", rpm:"libwsutil8~2.4.11~48.35.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil8-debuginfo", rpm:"libwsutil8-debuginfo~2.4.11~48.35.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~2.4.11~48.35.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debuginfo", rpm:"wireshark-debuginfo~2.4.11~48.35.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debugsource", rpm:"wireshark-debugsource~2.4.11~48.35.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-gtk", rpm:"wireshark-gtk~2.4.11~48.35.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-gtk-debuginfo", rpm:"wireshark-gtk-debuginfo~2.4.11~48.35.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libwireshark9", rpm:"libwireshark9~2.4.11~48.35.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark9-debuginfo", rpm:"libwireshark9-debuginfo~2.4.11~48.35.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap7", rpm:"libwiretap7~2.4.11~48.35.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap7-debuginfo", rpm:"libwiretap7-debuginfo~2.4.11~48.35.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwscodecs1", rpm:"libwscodecs1~2.4.11~48.35.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwscodecs1-debuginfo", rpm:"libwscodecs1-debuginfo~2.4.11~48.35.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil8", rpm:"libwsutil8~2.4.11~48.35.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil8-debuginfo", rpm:"libwsutil8-debuginfo~2.4.11~48.35.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~2.4.11~48.35.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debuginfo", rpm:"wireshark-debuginfo~2.4.11~48.35.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debugsource", rpm:"wireshark-debugsource~2.4.11~48.35.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-gtk", rpm:"wireshark-gtk~2.4.11~48.35.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-gtk-debuginfo", rpm:"wireshark-gtk-debuginfo~2.4.11~48.35.1", rls:"SLES12.0SP3"))) {
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
