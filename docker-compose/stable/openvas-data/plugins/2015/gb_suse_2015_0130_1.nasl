# Copyright (C) 2015 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of their respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850630");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2015-01-24 05:48:38 +0100 (Sat, 24 Jan 2015)");
  script_cve_id("CVE-2014-3569", "CVE-2014-3570", "CVE-2014-3571", "CVE-2014-3572", "CVE-2014-8275", "CVE-2015-0204", "CVE-2015-0205", "CVE-2015-0206");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("openSUSE: Security Advisory for openssl (openSUSE-SU-2015:0130-1)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"openssl was updated to 1.0.1k to fix various security issues and bugs.

  The following issues were fixed:

  * CVE-2014-3570 (bsc#912296): Bignum squaring (BN_sqr) may have produced
  incorrect results on some platforms, including x86_64.

  * CVE-2014-3571 (bsc#912294): Fixed crash in dtls1_get_record whilst in
  the listen state where you get two separate reads performed - one for
  the header and one for the body of the handshake record.

  * CVE-2014-3572 (bsc#912015): Don't accept a handshake using an ephemeral
  ECDH ciphersuites with the server key exchange message omitted.

  * CVE-2014-8275 (bsc#912018): Fixed various certificate fingerprint issues.

  * CVE-2015-0204 (bsc#912014): Only allow ephemeral RSA keys in export
  ciphersuites

  * CVE-2015-0205 (bsc#912293): A fixwas added to prevent use of DH client
  certificates without sending certificate verify message.

  * CVE-2015-0206 (bsc#912292): A memory leak was fixed in
  dtls1_buffer_record.");

  script_tag(name:"affected", value:"openssl on openSUSE 13.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"openSUSE-SU", value:"2015:0130-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE13.1") {
  if(!isnull(res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~1.0.1k~11.64.2", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0", rpm:"libopenssl1_0_0~1.0.1k~11.64.2", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-debuginfo", rpm:"libopenssl1_0_0-debuginfo~1.0.1k~11.64.2", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1k~11.64.2", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~1.0.1k~11.64.2", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-debugsource", rpm:"openssl-debugsource~1.0.1k~11.64.2", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-devel-32bit", rpm:"libopenssl-devel-32bit~1.0.1k~11.64.2", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-32bit", rpm:"libopenssl1_0_0-32bit~1.0.1k~11.64.2", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-debuginfo-32bit", rpm:"libopenssl1_0_0-debuginfo-32bit~1.0.1k~11.64.2", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-doc", rpm:"openssl-doc~1.0.1k~11.64.2", rls:"openSUSE13.1"))) {
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
