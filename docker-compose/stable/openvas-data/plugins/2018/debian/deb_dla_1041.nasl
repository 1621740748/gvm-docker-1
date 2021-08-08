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
  script_oid("1.3.6.1.4.1.25623.1.0.891041");
  script_version("2021-06-21T02:00:27+0000");
  script_cve_id("CVE-2017-10686", "CVE-2017-11111");
  script_name("Debian LTS: Security Advisory for nasm (DLA-1041-1)");
  script_tag(name:"last_modification", value:"2021-06-21 02:00:27 +0000 (Mon, 21 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-02-08 00:00:00 +0100 (Thu, 08 Feb 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-28 05:29:00 +0000 (Thu, 28 Mar 2019)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/07/msg00035.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_tag(name:"affected", value:"nasm on Debian Linux");

  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
2.10.01-1+deb7u1.

We recommend that you upgrade your nasm packages.");

  script_tag(name:"summary", value:"CVE-2017-10686
In Netwide Assembler (NASM) 2.14rc0, there are multiple heap use
after free vulnerabilities in the tool nasm. The related heap is
allocated in the token() function and freed in the detoken()
function (called by pp_getline()) - it is used again at multiple
positions later that could cause multiple damages. For example,
it causes a corrupted double-linked list in detoken(), a double
free or corruption in delete_Token(), and an out-of-bounds write
in detoken(). It has a high possibility to lead to a remote code
execution attack.

CVE-2017-11111
In Netwide Assembler (NASM) 2.14rc0, preproc.c allows remote
attackers to cause a denial of service (heap-based buffer
overflow and application crash) or possibly have unspecified
other impact via a crafted file.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"nasm", ver:"2.10.01-1+deb7u1", rls:"DEB7"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
