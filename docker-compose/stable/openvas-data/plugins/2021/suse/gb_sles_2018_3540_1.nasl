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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3540.1");
  script_cve_id("CVE-2016-10012", "CVE-2016-10708", "CVE-2017-15906", "CVE-2018-15473", "CVE-2018-15919");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:35 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-11 10:29:00 +0000 (Tue, 11 Sep 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3540-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3540-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183540-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh' package(s) announced via the SUSE-SU-2018:3540-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssh fixes the following issues:

Security issues fixed:
CVE-2018-15919: Remotely observable behaviour in auth-gss2.c in OpenSSH
 could be used by remote attackers to detect existence of users on a
 target system when GSS2 is in use. OpenSSH developers do not want to
 treat such a username enumeration (or 'oracle') as a vulnerability.
 (bsc#1106163)

CVE-2017-15906: The process_open function in sftp-server.c in OpenSSH
 did not properly prevent write operations in readonly mode, which
 allowed attackers to create zero-length files. (bsc#1065000, bsc#1106726)

CVE-2016-10708: sshd allowed remote attackers to cause a denial of
 service (NULL pointer dereference and daemon crash) via an
 out-of-sequence NEWKEYS message, as demonstrated by Honggfuzz, related
 to kex.c and packet.c. (bsc#1076957)

CVE-2018-15473: OpenSSH was prone to a user existance oracle
 vulnerability due to not delaying bailout for an invalid authenticating
 user until after the packet containing the request has been fully
 parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.
 (bsc#1105010)

CVE-2016-10012: Removed pre-auth compression support from the server to
 prevent possible cryptographic attacks. (bsc#1016370)

Bugs fixed:
Fixed failing 'AuthorizedKeysCommand' within a 'Match User' block in
 sshd_config (bsc#1105180)");

  script_tag(name:"affected", value:"'openssh' package(s) on SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Debuginfo 11-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"openssh", rpm:"openssh~6.2p2~0.41.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass", rpm:"openssh-askpass~6.2p2~0.41.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass-gnome", rpm:"openssh-askpass-gnome~6.2p2~0.41.5.1", rls:"SLES11.0SP3"))) {
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
