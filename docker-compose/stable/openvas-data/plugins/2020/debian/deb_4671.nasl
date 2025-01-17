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
  script_oid("1.3.6.1.4.1.25623.1.0.704671");
  script_version("2021-07-28T02:00:54+0000");
  script_cve_id("CVE-2020-6071", "CVE-2020-6072", "CVE-2020-6073", "CVE-2020-6077", "CVE-2020-6078", "CVE-2020-6079", "CVE-2020-6080");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-28 02:00:54 +0000 (Wed, 28 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-15 00:15:00 +0000 (Fri, 15 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-02 03:00:23 +0000 (Sat, 02 May 2020)");
  script_name("Debian: Security Advisory for vlc (DSA-4671-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(9|10)");

  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4671.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4671-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vlc'
  package(s) announced via the DSA-4671-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in the microdns plugin of the
VLC media player, which could result in denial of service or potentially
the execution of arbitrary code via malicious mDNS packets.");

  script_tag(name:"affected", value:"'vlc' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (stretch), these problems have been fixed
in version 3.0.10-0+deb9u1. This update disables the microdns plugin.

For the stable distribution (buster), these problems have been fixed in
version 3.0.10-0+deb10u1. This update disables the microdns plugin.

We recommend that you upgrade your vlc packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libvlc-bin", ver:"3.0.10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libvlc-dev", ver:"3.0.10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libvlc5", ver:"3.0.10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libvlccore-dev", ver:"3.0.10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libvlccore9", ver:"3.0.10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc", ver:"3.0.10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-bin", ver:"3.0.10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-data", ver:"3.0.10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-l10n", ver:"3.0.10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-nox", ver:"3.0.10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-access-extra", ver:"3.0.10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-base", ver:"3.0.10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-fluidsynth", ver:"3.0.10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-jack", ver:"3.0.10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-notify", ver:"3.0.10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-qt", ver:"3.0.10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-samba", ver:"3.0.10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-skins2", ver:"3.0.10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-svg", ver:"3.0.10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-video-output", ver:"3.0.10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-video-splitter", ver:"3.0.10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-visualization", ver:"3.0.10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-zvbi", ver:"3.0.10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libvlc-bin", ver:"3.0.10-0+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libvlc-dev", ver:"3.0.10-0+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libvlc5", ver:"3.0.10-0+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libvlccore-dev", ver:"3.0.10-0+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libvlccore9", ver:"3.0.10-0+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc", ver:"3.0.10-0+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-bin", ver:"3.0.10-0+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-data", ver:"3.0.10-0+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-l10n", ver:"3.0.10-0+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-access-extra", ver:"3.0.10-0+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-base", ver:"3.0.10-0+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-fluidsynth", ver:"3.0.10-0+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-jack", ver:"3.0.10-0+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-notify", ver:"3.0.10-0+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-qt", ver:"3.0.10-0+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-samba", ver:"3.0.10-0+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-skins2", ver:"3.0.10-0+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-svg", ver:"3.0.10-0+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-video-output", ver:"3.0.10-0+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-video-splitter", ver:"3.0.10-0+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-visualization", ver:"3.0.10-0+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-zvbi", ver:"3.0.10-0+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
