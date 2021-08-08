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
  script_oid("1.3.6.1.4.1.25623.1.0.892528");
  script_version("2021-02-08T07:52:32+0000");
  script_cve_id("CVE-2021-3185");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-02-08 07:52:32 +0000 (Mon, 08 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-01-19 04:00:03 +0000 (Tue, 19 Jan 2021)");
  script_name("Debian LTS: Security Advisory for gst-plugins-bad1.0 (DLA-2528-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/01/msg00016.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2528-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gst-plugins-bad1.0'
  package(s) announced via the DLA-2528-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Andrew Wesie discovered a buffer overflow in the H264 support of the
GStreamer multimedia framework, which could potentially result in the
execution of arbitrary code.");

  script_tag(name:"affected", value:"'gst-plugins-bad1.0' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, this problem has been fixed in version
1.10.4-1+deb9u1.

We recommend that you upgrade your gst-plugins-bad1.0 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"gir1.2-gst-plugins-bad-1.0", ver:"1.10.4-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-plugins-bad", ver:"1.10.4-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-plugins-bad-dbg", ver:"1.10.4-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-plugins-bad-doc", ver:"1.10.4-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgstreamer-plugins-bad1.0-0", ver:"1.10.4-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgstreamer-plugins-bad1.0-dev", ver:"1.10.4-1+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
