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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.1450.1");
  script_cve_id("CVE-2013-4927", "CVE-2013-4929", "CVE-2013-4930", "CVE-2013-4931", "CVE-2013-4932", "CVE-2013-4933", "CVE-2013-4934", "CVE-2013-4935");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:23 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-19 01:36:00 +0000 (Tue, 19 Sep 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:1450-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3|SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:1450-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20131450-1/");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.8.9.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the SUSE-SU-2013:1450-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This wireshark version update from 1.8.8 to 1.8.9 includes several security and general bug fixes. (bnc#831718) [link moved to references] > * The Bluetooth SDP dissector could go into a large loop CVE-2013-4927 wnpa-sec-2013-45 * The DIS dissector could go into a large loop CVE-2013-4929 wnpa-sec-2013-47 * The DVB-CI dissector could crash CVE-2013-4930 wnpa-sec-2013-48 * The GSM RR dissector (and possibly others) could go into a large loop CVE-2013-4931 wnpa-sec-2013-49 * The GSM A Common dissector could crash CVE-2013-4932 wnpa-sec-2013-50 * The Netmon file parser could crash CVE-2013-4933 CVE-2013-4934 wnpa-sec-2013-51 * The ASN.1 PER dissector could crash CVE-2013-4935 wnpa-sec-2013-52 The release also fixes various non-security issues. Please see the package changelog for details. Security Issues: * CVE-2013-4927 > * CVE-2013-4929 > * CVE-2013-4930 > * CVE-2013-4931 > * CVE-2013-4932 > * CVE-2013-4933 > * CVE-2013-4934 > * CVE-2013-4935 >");

  script_tag(name:"affected", value:"'wireshark' package(s) on SUSE Linux Enterprise Software Development Kit 11 SP3, SUSE Linux Enterprise Software Development Kit 11 SP2, SUSE Linux Enterprise Server 11 SP3, SUSE Linux Enterprise Server 11 SP2, SUSE Linux Enterprise Desktop 11 SP3, SUSE Linux Enterprise Desktop 11 SP2.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.8.9~0.2.5", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.8.9~0.2.5", rls:"SLES11.0SP2"))) {
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
