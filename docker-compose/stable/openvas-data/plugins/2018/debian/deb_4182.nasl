###############################################################################
# OpenVAS Vulnerability Test
#
# Auto-generated from advisory DSA 4182-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.704182");
  script_version("2021-06-22T02:00:27+0000");
  script_cve_id("CVE-2018-6056", "CVE-2018-6057", "CVE-2018-6060", "CVE-2018-6061", "CVE-2018-6062",
                "CVE-2018-6063", "CVE-2018-6064", "CVE-2018-6065", "CVE-2018-6066", "CVE-2018-6067",
                "CVE-2018-6068", "CVE-2018-6069", "CVE-2018-6070", "CVE-2018-6071", "CVE-2018-6072",
                "CVE-2018-6073", "CVE-2018-6074", "CVE-2018-6075", "CVE-2018-6076", "CVE-2018-6077",
                "CVE-2018-6078", "CVE-2018-6079", "CVE-2018-6080", "CVE-2018-6081", "CVE-2018-6082",
                "CVE-2018-6083", "CVE-2018-6085", "CVE-2018-6086", "CVE-2018-6087", "CVE-2018-6088",
                "CVE-2018-6089", "CVE-2018-6090", "CVE-2018-6091", "CVE-2018-6092", "CVE-2018-6093",
                "CVE-2018-6094", "CVE-2018-6095", "CVE-2018-6096", "CVE-2018-6097", "CVE-2018-6098",
                "CVE-2018-6099", "CVE-2018-6100", "CVE-2018-6101", "CVE-2018-6102", "CVE-2018-6103",
                "CVE-2018-6104", "CVE-2018-6105", "CVE-2018-6106", "CVE-2018-6107", "CVE-2018-6108",
                "CVE-2018-6109", "CVE-2018-6110", "CVE-2018-6111", "CVE-2018-6112", "CVE-2018-6113",
                "CVE-2018-6114", "CVE-2018-6116", "CVE-2018-6117");
  script_name("Debian Security Advisory DSA 4182-1 (chromium-browser - security update)");
  script_tag(name:"last_modification", value:"2021-06-22 02:00:27 +0000 (Tue, 22 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-04-28 00:00:00 +0200 (Sat, 28 Apr 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-29 19:41:00 +0000 (Tue, 29 Jan 2019)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4182.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");
  script_tag(name:"affected", value:"chromium-browser on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), security support for chromium
has been discontinued.

For the stable distribution (stretch), these problems have been fixed in
version 66.0.3359.117-1~deb9u1.

We recommend that you upgrade your chromium-browser packages.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/chromium-browser");
  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2018-6056
lokihardt discovered an error in the v8 javascript library.

CVE-2018-6057
Gal Beniamini discovered errors related to shared memory permissions.

CVE-2018-6060
Omair discovered a use-after-free issue in blink/webkit.

CVE-2018-6061
Guang Gong discovered a race condition in the v8 javascript library.

Description truncated. Please see the references for more information.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"chromedriver", ver:"66.0.3359.117-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"66.0.3359.117-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-driver", ver:"66.0.3359.117-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"66.0.3359.117-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-shell", ver:"66.0.3359.117-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-widevine", ver:"66.0.3359.117-1~deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}