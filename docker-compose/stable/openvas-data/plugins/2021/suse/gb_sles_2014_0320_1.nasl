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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.0320.1");
  script_cve_id("CVE-2009-5138", "CVE-2011-4108", "CVE-2012-0390", "CVE-2012-1569", "CVE-2012-1573", "CVE-2013-0169", "CVE-2013-1619", "CVE-2013-2116", "CVE-2014-0092");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:22 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2014-04-01 05:44:00 +0000 (Tue, 01 Apr 2014)");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:0320-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:0320-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20140320-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls' package(s) announced via the SUSE-SU-2014:0320-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The GnuTLS library received a critical security fix and other updates:

 * CVE-2014-0092: The X.509 certificate verification had incorrect error handling, which could lead to broken certificates marked as being valid.
 * CVE-2009-5138: A verification problem in handling V1 certificates could also lead to V1 certificates incorrectly being handled.
 * CVE-2013-2116: The _gnutls_ciphertext2compressed function in lib/gnutls_cipher.c in GnuTLS allowed remote attackers to cause a denial of service (buffer over-read and crash) via a crafted padding length.
 * CVE-2013-1619: The TLS implementation in GnuTLS did not properly consider timing side-channel attacks on a noncompliant MAC check operation during the processing of malformed CBC padding, which allows remote attackers to conduct distinguishing attacks and plaintext-recovery attacks via statistical analysis of timing data for crafted packets, a related issue to CVE-2013-0169. (Lucky13)
 * CVE-2012-1569: The asn1_get_length_der function in decoding.c in GNU Libtasn1 , as used in GnuTLS did not properly handle certain large length values, which allowed remote attackers to cause a denial of service (heap memory corruption and application crash) or possibly have unspecified other impact via a crafted ASN.1 structure.
 * CVE-2012-1573: gnutls_cipher.c in libgnutls in GnuTLS did not properly handle data encrypted with a block cipher,
which allowed remote attackers to cause a denial of service
(heap memory corruption and application crash) via a crafted record, as demonstrated by a crafted GenericBlockCipher structure.
 * CVE-2012-0390: The DTLS implementation in GnuTLS executed certain error-handling code only if there is a specific relationship between a padding length and the ciphertext size, which made it easier for remote attackers to recover partial plaintext via a timing side-channel attack, a related issue to CVE-2011-4108.

Also some non security bugs have been fixed:

 * Did some more s390x size_t vs int fixes. (bnc#536809,
bnc#659128)
 * re-enabled 'legacy negotiation' (bnc#554084)
 * fix safe-renegotiation for sle10sp3 and sle10sp4 bug
(bnc#554084)
 * fix bug bnc#536809, fix gnutls-cli to abort connection after detecting a bad certificate

Security Issue references:

 * CVE-2009-5138
>
 * CVE-2011-4108
>
 * CVE-2012-0390
>
 * CVE-2012-1569
>
 * CVE-2012-1573
>
 * CVE-2013-0169
>
 * CVE-2013-1619
>
 * CVE-2013-2116
>
 * CVE-2014-0092
>");

  script_tag(name:"affected", value:"'gnutls' package(s) on SUSE Linux Enterprise Server 10 SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~1.2.10~13.38.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-devel", rpm:"gnutls-devel~1.2.10~13.38.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-32bit", rpm:"gnutls-32bit~1.2.10~13.38.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-devel-32bit", rpm:"gnutls-devel-32bit~1.2.10~13.38.1", rls:"SLES10.0SP3"))) {
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
