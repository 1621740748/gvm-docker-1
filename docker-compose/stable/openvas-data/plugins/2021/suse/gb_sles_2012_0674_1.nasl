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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.0674.1");
  script_cve_id("CVE-2006-7250", "CVE-2011-4108", "CVE-2011-4109", "CVE-2011-4576", "CVE-2011-4619", "CVE-2012-0050", "CVE-2012-1165", "CVE-2012-2110", "CVE-2012-2131", "CVE-2012-2333");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:26 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-29 01:30:00 +0000 (Tue, 29 Aug 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:0674-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:0674-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20120674-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the SUSE-SU-2012:0674-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update of openssl fixes the following security issues:

 * Denial of Service or crash via CBC mode handling.
(CVE-2012-2333
> )
 * Incorrect integer conversions that could result in memory corruption. (CVE-2012-2110
> , CVE-2012-2131
> )
 * Potential memory leak in multithreaded key creation.
 * Symmetric crypto errors in PKCS7_decrypt.
 * Free headers after use in error message.
 * S/MIME verification may erroneously fail.
 * Tolerating bad MIME headers in ANS.1 parser.
(CVE-2012-1165
> , CVE-2006-7250
> )
 * DTLS DoS Attack. (CVE-2012-0050
> )
 * DTLS Plaintext Recovery Attack. (CVE-2011-4108
> )
 * Double-free in Policy Checks. (CVE-2011-4109
> )
 * Uninitialized SSL 3.0 Padding. (CVE-2011-4576
> )
 * SGC Restart DoS Attack. (CVE-2011-4619
> )");

  script_tag(name:"affected", value:"'openssl' package(s) on SUSE Linux Enterprise Server 10 SP3.");

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

if(release == "SLES10.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8a~18.45.63.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~0.9.8a~18.45.63.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-doc", rpm:"openssl-doc~0.9.8a~18.45.63.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-32bit", rpm:"openssl-32bit~0.9.8a~18.45.63.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-devel-32bit", rpm:"openssl-devel-32bit~0.9.8a~18.45.63.1", rls:"SLES10.0SP3"))) {
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
