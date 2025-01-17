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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1602.1");
  script_cve_id("CVE-2016-6293", "CVE-2017-14952", "CVE-2017-15422", "CVE-2017-17484", "CVE-2017-7867", "CVE-2017-7868");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:44 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-23 19:29:00 +0000 (Tue, 23 Apr 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1602-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1602-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181602-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icu' package(s) announced via the SUSE-SU-2018:1602-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for icu fixes the following issues:
- CVE-2016-6293: The uloc_acceptLanguageFromHTTP function in
 common/uloc.cpp did not ensure that there is a '\0' character at the end
 of a certain temporary array, which allows remote attackers to cause a
 denial of service (out-of-bounds read) or possibly have unspecified
 other impact via a call with a long httpAcceptLanguage argument.
 (bsc#990636)
- CVE-2017-7868: ICU had an out-of-bounds write caused by a heap-based
 buffer overflow related to the utf8TextAccess function in
 common/utext.cpp and the utext_moveIndex32* function. (bsc#1034674)
- CVE-2017-7867: ICU had an out-of-bounds write caused by a heap-based
 buffer overflow related to the utf8TextAccess function in
 common/utext.cpp and the utext_setNativeIndex* function. (bsc#1034678)
- CVE-2017-14952: Double free in i18n/zonemeta.cpp allowed remote
 attackers to execute arbitrary code via a crafted string, aka a
 'redundant UVector entry clean up function call' issue. (bsc#1067203)
- CVE-2017-17484:The ucnv_UTF8FromUTF8 function in ucnv_u8.cpp mishandled
 ucnv_convertEx calls for UTF-8 to UTF-8 conversion, which allows remote
 attackers to cause a denial of service (stack-based buffer overflow and
 application crash) or possibly have unspecified other impact via a
 crafted string, as demonstrated by ZNC. (bsc#1072193)
- CVE-2017-15422: An integer overflow in persian calendar calculation was
 fixed, which could show wrong years. (bsc#1077999)");

  script_tag(name:"affected", value:"'icu' package(s) on SUSE Linux Enterprise Software Development Kit 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Debuginfo 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libicu", rpm:"libicu~4.0~47.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu-doc", rpm:"libicu-doc~4.0~47.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu-32bit", rpm:"libicu-32bit~4.0~47.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu-x86", rpm:"libicu-x86~4.0~47.6.1", rls:"SLES11.0SP4"))) {
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
