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
  script_oid("1.3.6.1.4.1.25623.1.0.891032");
  script_version("2020-01-29T08:28:43+0000");
  script_name("Debian LTS: Security Advisory for unattended-upgrades (DLA-1032-1)");
  script_tag(name:"last_modification", value:"2020-01-29 08:28:43 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"creation_date", value:"2018-02-08 00:00:00 +0100 (Thu, 08 Feb 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/07/msg00024.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_tag(name:"affected", value:"unattended-upgrades on Debian Linux");

  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
0.79.5+wheezy3. Note that later unattended-upgrades version released
in later Debian versions do not exhibit the same behavior, as they use
the release codename (e.g. 'jessie') instead of the suite name
(e.g. 'oldstable') in the configuration file. So later releases will
transition correctly for future LTS releases.

We recommend that you upgrade your unattended-upgrades packages.");

  script_tag(name:"summary", value:"Since the release of the last Debian stable release ('stretch'),
Debian LTS ('wheezy') has been renamed 'oldoldstable', which broke
the unattended-upgrades package as described in bug #867169. Updates
would simply not be performed anymore.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"unattended-upgrades", ver:"0.79.5+wheezy3", rls:"DEB7"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
