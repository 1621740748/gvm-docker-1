# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.891568");
  script_version("2021-06-16T11:00:23+0000");
  script_cve_id("CVE-2016-5420", "CVE-2016-7141", "CVE-2016-7167", "CVE-2016-9586", "CVE-2018-16839",
                "CVE-2018-16842");
  script_name("Debian LTS: Security Advisory for curl (DLA-1568-1)");
  script_tag(name:"last_modification", value:"2021-06-16 11:00:23 +0000 (Wed, 16 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-11-07 00:00:00 +0100 (Wed, 07 Nov 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-13 11:29:00 +0000 (Tue, 13 Nov 2018)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/11/msg00005.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_tag(name:"affected", value:"curl on Debian Linux");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
7.38.0-4+deb8u13.

We recommend that you upgrade your curl packages.");

  script_tag(name:"summary", value:"Several vulnerabilities were discovered in cURL, an URL transfer
library.

CVE-2016-7141

When built with NSS and the libnsspem.so library is available at
runtime, allows a remote attacker to hijack the authentication of a
TLS connection by leveraging reuse of a previously loaded client
certificate from file for a connection for which no certificate has
been set, a different vulnerability than CVE-2016-5420.

CVE-2016-7167

Multiple integer overflows in the (1) curl_escape, (2)
curl_easy_escape, (3) curl_unescape, and (4) curl_easy_unescape
functions in libcurl allow attackers to have unspecified impact via
a string of length 0xffffffff, which triggers a heap-based buffer
overflow.

CVE-2016-9586

Curl is vulnerable to a buffer overflow when doing a large floating
point output in libcurl's implementation of the printf() functions.
If there are any applications that accept a format string from the
outside without necessary input filtering, it could allow remote
attacks.

CVE-2018-16839

Curl is vulnerable to a buffer overrun in the SASL authentication
code that may lead to denial of service.

CVE-2018-16842

Curl is vulnerable to a heap-based buffer over-read in the
tool_msgs.c:voutf() function that may result in information exposure
and denial of service.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"curl", ver:"7.38.0-4+deb8u13", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl3", ver:"7.38.0-4+deb8u13", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl3-dbg", ver:"7.38.0-4+deb8u13", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.38.0-4+deb8u13", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl3-nss", ver:"7.38.0-4+deb8u13", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl4-doc", ver:"7.38.0-4+deb8u13", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl4-gnutls-dev", ver:"7.38.0-4+deb8u13", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl4-nss-dev", ver:"7.38.0-4+deb8u13", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl4-openssl-dev", ver:"7.38.0-4+deb8u13", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
