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
  script_oid("1.3.6.1.4.1.25623.1.0.704892");
  script_version("2021-04-19T03:00:04+0000");
  script_cve_id("CVE-2021-23980");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-04-19 03:00:04 +0000 (Mon, 19 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-19 03:00:04 +0000 (Mon, 19 Apr 2021)");
  script_name("Debian: Security Advisory for python-bleach (DSA-4892-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4892.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4892-1");
  script_xref(name:"Advisory-ID", value:"DSA-4892-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-bleach'
  package(s) announced via the DSA-4892-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was reported that python-bleach, a whitelist-based HTML-sanitizing
library, is prone to a mutation XSS vulnerability in bleach.clean when
svg or math are in the allowed tags, 'p' or br are in allowed
tags, style, title, noscript, script, textarea, noframes,
iframe, or xmp
are in allowed tags and 'strip_comments=False' is
set.");

  script_tag(name:"affected", value:"'python-bleach' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (buster), this problem has been fixed in
version 3.1.2-0+deb10u2.

We recommend that you upgrade your python-bleach packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"python-bleach", ver:"3.1.2-0+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-bleach-doc", ver:"3.1.2-0+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-bleach", ver:"3.1.2-0+deb10u2", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
