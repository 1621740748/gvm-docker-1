###############################################################################
# OpenVAS Vulnerability Test
#
# Auto-generated from advisory DSA 4178-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.704178");
  script_version("2021-06-17T04:16:32+0000");
  script_cve_id("CVE-2018-10119", "CVE-2018-10120");
  script_name("Debian Security Advisory DSA 4178-1 (libreoffice - security update)");
  script_tag(name:"last_modification", value:"2021-06-17 04:16:32 +0000 (Thu, 17 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-04-20 00:00:00 +0200 (Fri, 20 Apr 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-05 21:21:00 +0000 (Tue, 05 Mar 2019)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4178.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB[89]");
  script_tag(name:"affected", value:"libreoffice on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), these problems have been fixed
in version 1:4.3.3-2+deb8u11.

For the stable distribution (stretch), these problems have been fixed in
version 1:5.2.7-1+deb9u4.

We recommend that you upgrade your libreoffice packages.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libreoffice");
  script_tag(name:"summary", value:"Two vulnerabilities were discovered in LibreOffice's code to parse
MS Word and Structured Storage files, which could result in denial of
service and potentially the execution of arbitrary code if a malformed
file is opened.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"gir1.2-lokdocview-0.1", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"liblibreofficekitgtk", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-avmedia-backend-gstreamer", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-avmedia-backend-vlc", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-base", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-base-core", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-base-drivers", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-calc", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-common", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-core", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-dev", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-dev-common", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-dev-doc", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-draw", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-evolution", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-gnome", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-gtk", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-gtk2", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-gtk3", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-ca", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-cs", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-da", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-de", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-dz", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-el", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-en-gb", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-en-us", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-es", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-et", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-eu", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-fi", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-fr", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-gl", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-hi", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-hu", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-it", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-ja", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-km", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-ko", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-nl", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-om", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-pl", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-pt", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-pt-br", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-ru", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-sk", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-sl", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-sv", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-tr", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-vi", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-zh-cn", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-zh-tw", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-impress", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-java-common", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-kde", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-af", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-am", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ar", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-as", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ast", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-be", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-bg", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-bn", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-br", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-bs", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ca", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-cs", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-cy", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-da", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-de", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-dz", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-el", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-en-gb", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-en-za", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-eo", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-es", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-et", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-eu", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-fa", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-fi", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-fr", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ga", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-gd", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-gl", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-gu", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-gug", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-he", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-hi", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-hr", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-hu", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-id", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-in", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-is", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-it", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ja", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ka", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-kk", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-km", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-kmr", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ko", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-lt", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-lv", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-mk", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ml", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-mn", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-mr", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-nb", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ne", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-nl", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-nn", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-nr", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-nso", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-oc", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-om", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-or", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-pa-in", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-pl", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-pt", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-pt-br", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ro", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ru", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-rw", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-si", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-sk", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-sl", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-sr", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ss", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-st", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-sv", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ta", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-te", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-tg", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-th", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-tn", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-tr", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ts", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ug", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-uk", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-uz", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ve", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-vi", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-xh", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-za", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-zh-cn", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-zh-tw", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-zu", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-librelogo", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-math", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-officebean", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-ogltrans", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-pdfimport", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-report-builder", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-report-builder-bin", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-script-provider-bsh", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-script-provider-js", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-script-provider-python", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-sdbc-hsqldb", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-sdbc-postgresql", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-style-breeze", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-style-galaxy", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-style-hicontrast", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-style-oxygen", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-style-sifr", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-style-tango", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-subsequentcheckbase", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-systray", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-writer", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreofficekit-data", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreofficekit-dev", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-uno", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uno-libs3", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ure", ver:"1:5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"browser-plugin-libreoffice", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-avmedia-backend-gstreamer", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-avmedia-backend-vlc", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-base", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-base-core", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-base-drivers", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-calc", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-common", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-core", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-dbg", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-dev", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-dev-doc", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-draw", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-emailmerge", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-evolution", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-gnome", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-gtk", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-gtk3", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-ca", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-cs", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-da", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-de", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-dz", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-el", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-en-gb", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-en-us", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-es", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-et", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-eu", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-fi", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-fr", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-gl", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-hi", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-hu", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-it", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-ja", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-km", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-ko", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-nl", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-om", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-pl", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-pt", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-pt-br", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-ru", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-sk", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-sl", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-sv", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-tr", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-vi", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-zh-cn", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-zh-tw", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-impress", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-java-common", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-kde", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-af", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ar", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-as", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ast", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-be", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-bg", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-bn", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-br", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-bs", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ca", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-cs", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-cy", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-da", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-de", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-dz", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-el", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-en-gb", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-en-za", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-eo", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-es", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-et", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-eu", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-fa", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-fi", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-fr", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ga", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-gd", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-gl", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-gu", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-he", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-hi", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-hr", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-hu", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-id", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-in", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-is", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-it", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ja", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ka", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-kk", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-km", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-kmr", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ko", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ku", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-lt", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-lv", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-mk", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ml", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-mn", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-mr", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-nb", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ne", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-nl", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-nn", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-nr", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-nso", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-oc", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-om", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-or", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-pa-in", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-pl", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-pt", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-pt-br", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ro", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ru", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-rw", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-si", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-sk", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-sl", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-sr", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ss", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-st", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-sv", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ta", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-te", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-tg", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-th", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-tn", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-tr", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ts", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ug", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-uk", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-uz", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ve", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-vi", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-xh", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-za", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-zh-cn", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-zh-tw", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-zu", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-librelogo", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-math", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-officebean", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-ogltrans", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-pdfimport", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-presentation-minimizer", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-presenter-console", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-report-builder", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-report-builder-bin", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-script-provider-bsh", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-script-provider-js", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-script-provider-python", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-sdbc-firebird", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-sdbc-hsqldb", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-sdbc-postgresql", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-style-crystal", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-style-galaxy", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-style-hicontrast", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-style-oxygen", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-style-sifr", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-style-tango", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-subsequentcheckbase", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-writer", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-uno", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-uno", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uno-libs3", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uno-libs3-dbg", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ure", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ure-dbg", ver:"1:4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}

# nb: Those are using a different version scheme, take care of this when overwriting this LSC...
if(!isnull(res = isdpkgvuln(pkg:"fonts-opensymbol", ver:"2:102.7+LibO5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-mysql-connector", ver:"1.0.2+LibO5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-nlpsolver", ver:"0.9+LibO5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-wiki-publisher", ver:"1.2.0+LibO5.2.7-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fonts-opensymbol", ver:"2:102.6+LibO4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-mysql-connector", ver:"1.0.2+LibO4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libreoffice-wiki-publisher", ver:"1.1.2+LibO4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-dtd-officedocument1.0", ver:"2:1.0+LibO4.3.3-2+deb8u11", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
