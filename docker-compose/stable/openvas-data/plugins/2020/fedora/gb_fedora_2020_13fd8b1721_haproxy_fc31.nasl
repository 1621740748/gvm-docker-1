# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.877719");
  script_version("2021-07-16T11:00:51+0000");
  script_cve_id("CVE-2020-11100");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-16 11:00:51 +0000 (Fri, 16 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-24 16:15:00 +0000 (Thu, 24 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-04-30 03:14:30 +0000 (Thu, 30 Apr 2020)");
  script_name("Fedora: Security Advisory for haproxy (FEDORA-2020-13fd8b1721)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC31");

  script_xref(name:"FEDORA", value:"2020-13fd8b1721");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/264C7UL3X7L7QE74ZJ557IOUFS3J4QQC");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'haproxy'
  package(s) announced via the FEDORA-2020-13fd8b1721 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"HAProxy is a TCP/HTTP reverse proxy which is particularly suited for high
availability environments. Indeed, it can:

  - route HTTP requests depending on statically assigned cookies

  - spread load among several servers while assuring server persistence
   through the use of HTTP cookies

  - switch to backup servers in the event a main one fails

  - accept connections to special ports dedicated to service monitoring

  - stop accepting connections without breaking existing ones

  - add, modify, and delete HTTP headers in both directions

  - block requests matching particular patterns

  - report detailed status to authenticated users from a URI
   intercepted from the application");

  script_tag(name:"affected", value:"'haproxy' package(s) on Fedora 31.");

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

if(release == "FC31") {

  if(!isnull(res = isrpmvuln(pkg:"haproxy", rpm:"haproxy~2.0.14~1.fc31", rls:"FC31"))) {
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
