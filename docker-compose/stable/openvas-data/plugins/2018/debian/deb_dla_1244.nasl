# Copyright (C) 2018 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.891244");
  script_version("2020-01-29T08:33:43+0000");
  script_name("Debian LTS: Security Advisory for ca-certificates (DLA-1244-1)");
  script_tag(name:"last_modification", value:"2020-01-29 08:33:43 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"creation_date", value:"2018-01-16 00:00:00 +0100 (Tue, 16 Jan 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/01/msg00017.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_tag(name:"affected", value:"ca-certificates on Debian Linux");

  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
20130119+deb7u2.

We recommend that you upgrade your ca-certificates packages.");

  script_tag(name:"summary", value:"This release does a complete update of the CA list. This includes
removing the StartCom and WoSign certificates to as they are now
untrusted by the major browser vendors.

This includes 1024-bit root certificates (#858064) and untrusted StartCom and
WoSign certificates (#858539) which have been removed, as they are deemed to
untrustworthy.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"ca-certificates", ver:"20130119+deb7u2", rls:"DEB7"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
