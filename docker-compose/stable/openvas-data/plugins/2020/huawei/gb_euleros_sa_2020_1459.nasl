# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1459");
  script_version("2021-08-03T02:00:56+0000");
  script_cve_id("CVE-2017-13720", "CVE-2017-13722", "CVE-2017-16611");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-08-03 02:00:56 +0000 (Tue, 03 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-13 02:29:00 +0000 (Mon, 13 Nov 2017)");
  script_tag(name:"creation_date", value:"2020-04-16 05:55:47 +0000 (Thu, 16 Apr 2020)");
  script_name("Huawei EulerOS: Security Advisory for libXfont (EulerOS-SA-2020-1459)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.2\.2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1459");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1459");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'libXfont' package(s) announced via the EulerOS-SA-2020-1459 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In libXfont before 1.5.4 and libXfont2 before 2.0.3, a local attacker can open (but not read) files on the system as root, triggering tape rewinds, watchdogs, or similar mechanisms that can be triggered by opening files.(CVE-2017-16611)

In the pcfGetProperties function in bitmap/pcfread.c in libXfont through 1.5.2 and 2.x before 2.0.2, a missing boundary check (for PCF files) could be used by local attackers authenticated to an Xserver for a buffer over-read, for information disclosure or a crash of the X server.(CVE-2017-13722)

In the PatternMatch function in fontfile/fontdir.c in libXfont through 1.5.2 and 2.x before 2.0.2, an attacker with access to an X connection can cause a buffer over-read during pattern matching of fonts, leading to information disclosure or a crash (denial of service). This occurs because '\0' characters are incorrectly skipped in situations involving ? characters.(CVE-2017-13720)");

  script_tag(name:"affected", value:"'libXfont' package(s) on Huawei EulerOS Virtualization 3.0.2.2.");

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

if(release == "EULEROSVIRT-3.0.2.2") {

  if(!isnull(res = isrpmvuln(pkg:"libXfont", rpm:"libXfont~1.5.2~1.h2.eulerosv2r7", rls:"EULEROSVIRT-3.0.2.2"))) {
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
