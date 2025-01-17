###############################################################################
# OpenVAS Vulnerability Test
#
# Auto-generated from advisory DSA 4116-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704116");
  script_version("2021-06-18T11:51:03+0000");
  script_cve_id("CVE-2018-6791");
  script_name("Debian Security Advisory DSA 4116-1 (plasma-workspace - security update)");
  script_tag(name:"last_modification", value:"2021-06-18 11:51:03 +0000 (Fri, 18 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-02-16 00:00:00 +0100 (Fri, 16 Feb 2018)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4116.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");
  script_tag(name:"affected", value:"plasma-workspace on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (stretch), this problem has been fixed in
version 4:5.8.6-2.1+deb9u1.

We recommend that you upgrade your plasma-workspace packages.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/plasma-workspace");
  script_tag(name:"summary", value:"Krzysztof Sieluzycki discovered that the notifier for removable devices
in the KDE Plasma workspace performed insufficient sanitisation of
FAT/VFAT volume labels, which could result in the execution of arbitrary
shell commands if a removable device with a malformed disk label is
mounted.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libkworkspace5-5", ver:"4:5.8.6-2.1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libplasma-geolocation-interface5", ver:"4:5.8.6-2.1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtaskmanager6", ver:"4:5.8.6-2.1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libweather-ion7", ver:"4:5.8.6-2.1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"plasma-workspace", ver:"4:5.8.6-2.1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"plasma-workspace-dev", ver:"4:5.8.6-2.1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"plasma-workspace-wayland", ver:"4:5.8.6-2.1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sddm-theme-breeze", ver:"4:5.8.6-2.1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sddm-theme-debian-breeze", ver:"4:5.8.6-2.1+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}