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
  script_oid("1.3.6.1.4.1.25623.1.0.892670");
  script_version("2021-06-15T08:02:31+0000");
  script_cve_id("CVE-2021-23017");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-06-15 08:02:31 +0000 (Tue, 15 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-05-31 03:00:13 +0000 (Mon, 31 May 2021)");
  script_name("Debian LTS: Security Advisory for nginx (DLA-2670-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/05/msg00025.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2670-1");
  script_xref(name:"Advisory-ID", value:"DLA-2670-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/989095");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nginx'
  package(s) announced via the DLA-2670-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Luis Merino, Markus Vervier and Eric Sesterhenn discovered an off-by-one
in Nginx, a high-performance web and reverse proxy server, which could
result in denial of service and potentially the execution of arbitrary
code.");

  script_tag(name:"affected", value:"'nginx' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, this problem has been fixed in version
1.10.3-1+deb9u6.

We recommend that you upgrade your nginx packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-http-auth-pam", ver:"1.10.3-1+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-http-cache-purge", ver:"1.10.3-1+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-http-dav-ext", ver:"1.10.3-1+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-http-echo", ver:"1.10.3-1+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-http-fancyindex", ver:"1.10.3-1+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-http-geoip", ver:"1.10.3-1+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-http-headers-more-filter", ver:"1.10.3-1+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-http-image-filter", ver:"1.10.3-1+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-http-lua", ver:"1.10.3-1+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-http-ndk", ver:"1.10.3-1+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-http-perl", ver:"1.10.3-1+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-http-subs-filter", ver:"1.10.3-1+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-http-uploadprogress", ver:"1.10.3-1+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-http-upstream-fair", ver:"1.10.3-1+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-http-xslt-filter", ver:"1.10.3-1+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-mail", ver:"1.10.3-1+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-nchan", ver:"1.10.3-1+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-stream", ver:"1.10.3-1+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nginx", ver:"1.10.3-1+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nginx-common", ver:"1.10.3-1+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nginx-doc", ver:"1.10.3-1+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nginx-extras", ver:"1.10.3-1+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nginx-full", ver:"1.10.3-1+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nginx-light", ver:"1.10.3-1+deb9u6", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
