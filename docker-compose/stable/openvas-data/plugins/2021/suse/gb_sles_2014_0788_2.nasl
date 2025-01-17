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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.0788.2");
  script_cve_id("CVE-2014-3466", "CVE-2014-3467", "CVE-2014-3468", "CVE-2014-3469");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:20 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-16 14:30:00 +0000 (Mon, 16 Nov 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:0788-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4|SLES10\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:0788-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20140788-2/");
  script_xref(name:"URL", value:"http://www.gnutls.org/security.html#GNUTLS-SA-2014-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'GnuTLS' package(s) announced via the SUSE-SU-2014:0788-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GnuTLS has been patched to ensure proper parsing of session ids during the TLS/SSL handshake. Additionally three issues inherited from libtasn1 have been fixed.

Further information is available at [link moved to references] These security issues have been fixed:
 * Possible memory corruption during connect (CVE-2014-3466)
 * Multiple boundary check issues could allow DoS (CVE-2014-3467)
 * asn1_get_bit_der() can return negative bit length (CVE-2014-3468)
 * Possible DoS by NULL pointer dereference (CVE-2014-3469)
Security Issue references:
 * CVE-2014-3466");

  script_tag(name:"affected", value:"'GnuTLS' package(s) on SUSE Linux Enterprise Server 10 SP4, SUSE Linux Enterprise Server 10 SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~1.2.10~13.40.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-devel", rpm:"gnutls-devel~1.2.10~13.40.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-32bit", rpm:"gnutls-32bit~1.2.10~13.40.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-devel-32bit", rpm:"gnutls-devel-32bit~1.2.10~13.40.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES10.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~1.2.10~13.40.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-devel", rpm:"gnutls-devel~1.2.10~13.40.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-32bit", rpm:"gnutls-32bit~1.2.10~13.40.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-devel-32bit", rpm:"gnutls-devel-32bit~1.2.10~13.40.1", rls:"SLES10.0SP3"))) {
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
