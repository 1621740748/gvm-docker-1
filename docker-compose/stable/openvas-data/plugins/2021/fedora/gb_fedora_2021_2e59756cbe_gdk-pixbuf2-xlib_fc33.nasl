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
  script_oid("1.3.6.1.4.1.25623.1.0.878960");
  script_version("2021-06-07T06:36:41+0000");
  script_cve_id("CVE-2021-20240", "CVE-2020-29385");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"last_modification", value:"2021-06-07 06:36:41 +0000 (Mon, 07 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-02-24 04:05:45 +0000 (Wed, 24 Feb 2021)");
  script_name("Fedora: Security Advisory for gdk-pixbuf2-xlib (FEDORA-2021-2e59756cbe)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC33");

  script_xref(name:"Advisory-ID", value:"FEDORA-2021-2e59756cbe");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DQ3DRKCETN7AOZINESLXEYSCFRAUHMLL");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdk-pixbuf2-xlib'
  package(s) announced via the FEDORA-2021-2e59756cbe advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"gdk-pixbuf2-xlib contains the deprecated API for integrating gdk-pixbuf2 with
Xlib data types.

This library was originally shipped by gdk-pixbuf2, and has
since been moved out of the original repository.

No newly written code should ever use this library.

If your existing code depends on gdk-pixbuf2-xlib, then you&#39, re strongly
encouraged to port away from it.");

  script_tag(name:"affected", value:"'gdk-pixbuf2-xlib' package(s) on Fedora 33.");

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

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf2-xlib", rpm:"gdk-pixbuf2-xlib~2.40.2~2.fc33", rls:"FC33"))) {
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