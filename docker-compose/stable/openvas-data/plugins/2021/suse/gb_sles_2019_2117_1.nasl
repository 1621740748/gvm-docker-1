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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2117.1");
  script_cve_id("CVE-2018-10892", "CVE-2019-13509", "CVE-2019-14271", "CVE-2019-5736");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:20 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-28 13:15:00 +0000 (Wed, 28 Aug 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2117-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2117-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192117-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'containerd, docker, docker-runc, golang-github-docker-libnetwork' package(s) announced via the SUSE-SU-2019:2117-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for containerd, docker, docker-runc,
golang-github-docker-libnetwork fixes the following issues:

Docker:
CVE-2019-14271: Fixed a code injection if the nsswitch facility
 dynamically loaded a library inside a chroot (bsc#1143409).

CVE-2019-13509: Fixed an information leak in the debug log (bsc#1142160).

Update to version 19.03.1-ce, see changelog at
 /usr/share/doc/packages/docker/CHANGELOG.md (bsc#1142413, bsc#1139649).

runc:
Use %config(noreplace) for /etc/docker/daemon.json (bsc#1138920).

Update to runc 425e105d5a03, which is required by Docker (bsc#1139649).

containerd:
CVE-2019-5736: Fixed a container breakout vulnerability (bsc#1121967).

Update to containerd v1.2.6, which is required by docker (bsc#1139649).

golang-github-docker-libnetwork:
Update to version git.fc5a7d91d54cc98f64fc28f9e288b46a0bee756c, which is
 required by docker (bsc#1142413, bsc#1139649).");

  script_tag(name:"affected", value:"'containerd, docker, docker-runc, golang-github-docker-libnetwork' package(s) on SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15, SUSE Linux Enterprise Module for Containers 15-SP1, SUSE Linux Enterprise Module for Containers 15.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"containerd", rpm:"containerd~1.2.6~5.16.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~19.03.1_ce~6.26.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~19.03.1_ce~6.26.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-libnetwork", rpm:"docker-libnetwork~0.7.0.1+gitr2800_fc5a7d91d54c~4.15.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-libnetwork-debuginfo", rpm:"docker-libnetwork-debuginfo~0.7.0.1+gitr2800_fc5a7d91d54c~4.15.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-runc", rpm:"docker-runc~1.0.0rc8+gitr3826_425e105d5a03~6.21.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-runc-debuginfo", rpm:"docker-runc-debuginfo~1.0.0rc8+gitr3826_425e105d5a03~6.21.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~19.03.1_ce~6.26.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"containerd", rpm:"containerd~1.2.6~5.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~19.03.1_ce~6.26.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~19.03.1_ce~6.26.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-libnetwork", rpm:"docker-libnetwork~0.7.0.1+gitr2800_fc5a7d91d54c~4.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-libnetwork-debuginfo", rpm:"docker-libnetwork-debuginfo~0.7.0.1+gitr2800_fc5a7d91d54c~4.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-runc", rpm:"docker-runc~1.0.0rc8+gitr3826_425e105d5a03~6.21.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-runc-debuginfo", rpm:"docker-runc-debuginfo~1.0.0rc8+gitr3826_425e105d5a03~6.21.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~19.03.1_ce~6.26.2", rls:"SLES15.0"))) {
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
