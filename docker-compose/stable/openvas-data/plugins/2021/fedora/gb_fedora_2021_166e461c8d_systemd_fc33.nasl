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
  script_oid("1.3.6.1.4.1.25623.1.0.879878");
  script_version("2021-08-04T07:55:07+0000");
  script_cve_id("CVE-2020-13529", "CVE-2021-33910");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2021-08-04 07:55:07 +0000 (Wed, 04 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-07-27 03:23:45 +0000 (Tue, 27 Jul 2021)");
  script_name("Fedora: Security Advisory for systemd (FEDORA-2021-166e461c8d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC33");

  script_xref(name:"Advisory-ID", value:"FEDORA-2021-166e461c8d");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/42TMJVNYRY65B4QCJICBYOEIVZV3KUYI");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd'
  package(s) announced via the FEDORA-2021-166e461c8d advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"systemd is a system and service manager that runs as PID 1 and starts
the rest of the system. It provides aggressive parallelization
capabilities, uses socket and D-Bus activation for starting services,
offers on-demand starting of daemons, keeps track of processes using
Linux control groups, maintains mount and automount points, and
implements an elaborate transactional dependency-based service control
logic. systemd supports SysV and LSB init scripts and works as a
replacement for sysvinit. Other parts of this package are a logging daemon,
utilities to control basic system configuration like the hostname,
date, locale, maintain a list of logged-in users, system accounts,
runtime directories and settings, and daemons to manage simple network
configuration, network time synchronization, log forwarding, and name
resolution.

This package was built from the 246.15-stable branch of systemd.");

  script_tag(name:"affected", value:"'systemd' package(s) on Fedora 33.");

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

if(release == "FC33") {

  if(!isnull(res = isrpmvuln(pkg:"systemd", rpm:"systemd~246.15~1.fc33", rls:"FC33"))) {
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