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
  script_oid("1.3.6.1.4.1.25623.1.0.892364");
  script_version("2021-07-26T02:01:39+0000");
  script_cve_id("CVE-2019-16869", "CVE-2019-20444", "CVE-2019-20445", "CVE-2020-11612", "CVE-2020-7238");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-26 10:15:00 +0000 (Mon, 26 Apr 2021)");
  script_tag(name:"creation_date", value:"2020-09-05 03:00:17 +0000 (Sat, 05 Sep 2020)");
  script_name("Debian LTS: Security Advisory for netty (DLA-2364-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/09/msg00003.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2364-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/950966");
  script_xref(name:"URL", value:"https://bugs.debian.org/950967");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'netty'
  package(s) announced via the DLA-2364-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in netty, a Java NIO
client/server socket framework.

CVE-2019-20444

HttpObjectDecoder.java in Netty before 4.1.44 allows an HTTP header
that lacks a colon, which might be interpreted as a separate header
with an incorrect syntax, or might be interpreted as an 'invalid
fold.'

CVE-2019-20445

HttpObjectDecoder.java in Netty before 4.1.44 allows a Content-Length
header to be accompanied by a second Content-Length header, or by a
Transfer-Encoding header.

CVE-2020-7238

Netty 4.1.43.Final allows HTTP Request Smuggling because it
mishandles Transfer-Encoding whitespace (such as a
[space]Transfer-Encoding:chunked line) and a later Content-Length
header. This issue exists because of an incomplete fix for
CVE-2019-16869.

CVE-2020-11612

The ZlibDecoders in Netty 4.1.x before 4.1.46 allow for unbounded
memory allocation while decoding a ZlibEncoded byte stream. An
attacker could send a large ZlibEncoded byte stream to the Netty
server, forcing the server to allocate all of its free memory to a
single decoder.");

  script_tag(name:"affected", value:"'netty' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
1:4.1.7-2+deb9u2.

We recommend that you upgrade your netty packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libnetty-java", ver:"1:4.1.7-2+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
