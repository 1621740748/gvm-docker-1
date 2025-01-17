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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2514");
  script_version("2021-08-05T02:01:00+0000");
  script_cve_id("CVE-2014-9745", "CVE-2014-9747", "CVE-2015-9381", "CVE-2015-9382", "CVE-2015-9383");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-08-05 02:01:00 +0000 (Thu, 05 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-10 03:15:00 +0000 (Tue, 10 Sep 2019)");
  script_tag(name:"creation_date", value:"2020-01-23 13:03:01 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for freetype (EulerOS-SA-2019-2514)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2514");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2514");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'freetype' package(s) announced via the EulerOS-SA-2019-2514 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The parse_encoding function in type1/t1load.c in FreeType before 2.5.3 allows remote attackers to cause a denial of service (infinite loop) via a 'broken number-with-base' in a Postscript stream, as demonstrated by 8#garbage.(CVE-2014-9745)

The t42_parse_encoding function in type42/t42parse.c in FreeType before 2.5.4 does not properly update the current position for immediates-only mode, which allows remote attackers to cause a denial of service (infinite loop) via a Type42 font.(CVE-2014-9747)

FreeType before 2.6.1 has a buffer over-read in skip_comment in psaux/psobjs.c because ps_parser_skip_PS_token is mishandled in an FT_New_Memory_Face operation.(CVE-2015-9382)

FreeType before 2.6.2 has a heap-based buffer over-read in tt_cmap14_validate in sfnt/ttcmap.c.(CVE-2015-9383)

FreeType before 2.6.1 has a heap-based buffer over-read in T1_Get_Private_Dict in type1/t1parse.c.(CVE-2015-9381)");

  script_tag(name:"affected", value:"'freetype' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"freetype", rpm:"freetype~2.4.11~10_1.1.h8", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype-devel", rpm:"freetype-devel~2.4.11~10_1.1.h8", rls:"EULEROS-2.0SP2"))) {
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
