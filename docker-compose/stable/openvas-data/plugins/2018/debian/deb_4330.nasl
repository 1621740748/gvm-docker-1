###############################################################################
# OpenVAS Vulnerability Test
#
# Auto-generated from advisory DSA 4330-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.704330");
  script_version("2021-06-21T03:34:17+0000");
  script_cve_id("CVE-2018-17462", "CVE-2018-17463", "CVE-2018-17464", "CVE-2018-17465", "CVE-2018-17466",
                "CVE-2018-17467", "CVE-2018-17468", "CVE-2018-17469", "CVE-2018-17470", "CVE-2018-17471",
                "CVE-2018-17473", "CVE-2018-17474", "CVE-2018-17475", "CVE-2018-17476", "CVE-2018-17477",
                "CVE-2018-5179");
  script_name("Debian Security Advisory DSA 4330-1 (chromium-browser - security update)");
  script_tag(name:"last_modification", value:"2021-06-21 03:34:17 +0000 (Mon, 21 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-11-02 00:00:00 +0100 (Fri, 02 Nov 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4330.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");
  script_tag(name:"affected", value:"chromium-browser on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (stretch), these problems have been fixed in
version 70.0.3538.67-1~deb9u1.

We recommend that you upgrade your chromium-browser packages.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/chromium-browser");
  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2018-5179
Yannic Boneberger discovered an error in the ServiceWorker implementation.

CVE-2018-17462
Ned Williamson and Niklas Baumstark discovered a way to escape the sandbox.

CVE-2018-17463
Ned Williamson and Niklas Baumstark discovered a remote code execution
issue in the v8 javascript library.

CVE-2018-17464
xisigr discovered a URL spoofing issue.

CVE-2018-17465
Lin Zuojian discovered a use-after-free issue in the v8 javascript
library.

CVE-2018-17466
Omair discovered a memory corruption issue in the angle library.

CVE-2018-17467
Khalil Zhani discovered a URL spoofing issue.

CVE-2018-17468
Jams Lee discovered an information disclosure issue.

CVE-2018-17469
Zhen Zhou discovered a buffer overflow issue in the pdfium library.

CVE-2018-17470
Zhe Jin discovered a memory corruption issue in the GPU backend
implementation.

CVE-2018-17471
Lnyas Zhang discovered an issue with the full screen user interface.

CVE-2018-17473
Khalil Zhani discovered a URL spoofing issue.

CVE-2018-17474
Zhe Jin discovered a use-after-free issue.

CVE-2018-17475
Vladimir Metnew discovered a URL spoofing issue.

CVE-2018-17476
Khalil Zhani discovered an issue with the full screen user interface.

CVE-2018-17477
Aaron Muir Hamilton discovered a user interface spoofing issue in the
extensions pane.

This update also fixes a buffer overflow in the embedded lcms library included
with chromium.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"chromedriver", ver:"70.0.3538.67-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"70.0.3538.67-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-driver", ver:"70.0.3538.67-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"70.0.3538.67-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-shell", ver:"70.0.3538.67-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-widevine", ver:"70.0.3538.67-1~deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
