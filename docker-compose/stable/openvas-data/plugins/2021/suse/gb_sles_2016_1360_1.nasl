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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1360.1");
  script_cve_id("CVE-2016-0702", "CVE-2016-2105", "CVE-2016-2106", "CVE-2016-2108", "CVE-2016-2109");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:06 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1360-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1360-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161360-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the SUSE-SU-2016:1360-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for OpenSSL fixes the following security issues:
CVE-2016-2105: EVP_EncodeUpdate overflow (bsc#977614)
CVE-2016-2106: EVP_EncryptUpdate overflow (bsc#977615)
CVE-2016-2108: Memory corruption in the ASN.1 encoder (bsc#977617)
CVE-2016-2109: ASN.1 BIO excessive memory allocation (bsc#976942)
CVE-2016-0702: Side channel attack on modular exponentiation 'CacheBleed' (bsc#968050)
Additionally, the following non-security issues have been fixed:
Fix buffer overrun in ASN1_parse. (bsc#976943)
Allow weak DH groups. (bsc#973223)
Security Issues:
CVE-2016-2105 CVE-2016-2106 CVE-2016-2108 CVE-2016-2109 CVE-2016-0702");

  script_tag(name:"affected", value:"'openssl' package(s) on SUSE Linux Enterprise Server 10 SP4.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8a~18.96.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~0.9.8a~18.96.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-doc", rpm:"openssl-doc~0.9.8a~18.96.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-32bit", rpm:"openssl-32bit~0.9.8a~18.96.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-devel-32bit", rpm:"openssl-devel-32bit~0.9.8a~18.96.1", rls:"SLES10.0SP4"))) {
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
