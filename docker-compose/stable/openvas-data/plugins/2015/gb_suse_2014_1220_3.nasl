# Copyright (C) 2015 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851008");
  script_version("2020-01-31T07:58:03+0000");
  script_tag(name:"last_modification", value:"2020-01-31 07:58:03 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2015-10-16 16:35:32 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2014-1568");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SUSE: Security Advisory for mozilla-nss (SUSE-SU-2014:1220-3)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla-nss'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla NSS was updated to version 3.16.5 to fix a RSA certificate forgery
  issue.

  MFSA 2014-73 / CVE-2014-1568: Antoine Delignat-Lavaud, security researcher
  at Inria Paris in team Prosecco, reported an issue in Network Security
  Services (NSS) libraries affecting all versions. He discovered that NSS is
  vulnerable to a variant of a signature forgery attack previously published
  by Daniel Bleichenbacher. This is due to lenient parsing of ASN.1 values
  involved in a signature and could lead to the forging of RSA certificates.

  The Advanced Threat Research team at Intel Security also independently
  discovered and reported this issue.

  Security Issues:

  * CVE-2014-1568");

  script_tag(name:"affected", value:"mozilla-nss on SUSE Linux Enterprise Server 11 SP1 LTSS");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"SUSE-SU", value:"2014:1220-3");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES11\.0SP1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0SP1") {
  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.16.5~0.4.2.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.16.5~0.4.2.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.16.5~0.4.2.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.16.5~0.4.2.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.16.5~0.4.2.1", rls:"SLES11.0SP1"))) {
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
