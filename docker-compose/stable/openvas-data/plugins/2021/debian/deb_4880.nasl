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
  script_oid("1.3.6.1.4.1.25623.1.0.704880");
  script_version("2021-03-30T03:00:07+0000");
  script_cve_id("CVE-2021-28957");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-03-30 03:00:07 +0000 (Tue, 30 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-30 03:00:07 +0000 (Tue, 30 Mar 2021)");
  script_name("Debian: Security Advisory for lxml (DSA-4880-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4880.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4880-1");
  script_xref(name:"Advisory-ID", value:"DSA-4880-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lxml'
  package(s) announced via the DSA-4880-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kevin Chung discovered that lxml, a Python binding for the libxml2 and
libxslt libraries, did not properly sanitize its input. This would
allow a malicious user to mount a cross-site scripting attack.");

  script_tag(name:"affected", value:"'lxml' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (buster), this problem has been fixed in
version 4.3.2-1+deb10u3.

We recommend that you upgrade your lxml packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"python-lxml", ver:"4.3.2-1+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-lxml-dbg", ver:"4.3.2-1+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-lxml-doc", ver:"4.3.2-1+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-lxml", ver:"4.3.2-1+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-lxml-dbg", ver:"4.3.2-1+deb10u3", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
