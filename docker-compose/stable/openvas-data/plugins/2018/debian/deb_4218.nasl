###############################################################################
# OpenVAS Vulnerability Test
#
# Auto-generated from advisory DSA 4218-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.704218");
  script_version("2021-06-18T11:51:03+0000");
  script_cve_id("CVE-2017-9951", "CVE-2018-1000115", "CVE-2018-1000127");
  script_name("Debian Security Advisory DSA 4218-1 (memcached - security update)");
  script_tag(name:"last_modification", value:"2021-06-18 11:51:03 +0000 (Fri, 18 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-06-06 00:00:00 +0200 (Wed, 06 Jun 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4218.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB[89]");
  script_tag(name:"affected", value:"memcached on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), these problems have been fixed
in version 1.4.21-1.1+deb8u2.

For the stable distribution (stretch), these problems have been fixed in
version 1.4.33-1+deb9u1.

We recommend that you upgrade your memcached packages.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/memcached");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered in memcached, a high-performance
memory object caching system. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2017-9951
Daniel Shapira reported a heap-based buffer over-read in memcached
(resulting from an incomplete fix for CVE-2016-8705) triggered by
specially crafted requests to add/set a key and allowing a remote
attacker to cause a denial of service.

CVE-2018-1000115
It was reported that memcached listens to UDP by default. A remote
attacker can take advantage of it to use the memcached service as a
DDoS amplifier.

Default installations of memcached in Debian are not affected by
this issue as the installation defaults to listen only on localhost.
This update disables the UDP port by default. Listening on the UDP
can be re-enabled in the /etc/memcached.conf (cf.
/usr/share/doc/memcached/NEWS.Debian.gz).

CVE-2018-1000127
An integer overflow was reported in memcached, resulting in resource
leaks, data corruption, deadlocks or crashes.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"memcached", ver:"1.4.21-1.1+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"memcached", ver:"1.4.33-1+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}