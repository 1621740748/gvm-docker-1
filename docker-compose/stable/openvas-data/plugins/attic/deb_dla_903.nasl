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
  script_oid("1.3.6.1.4.1.25623.1.0.890903");
  script_version("2020-04-02T11:36:28+0000");
  script_name("Debian LTS: Security Advisory for hunspell-en-us (DLA-903-1)");
  script_tag(name:"last_modification", value:"2020-04-02 11:36:28 +0000 (Thu, 02 Apr 2020)");
  script_tag(name:"creation_date", value:"2018-01-17 00:00:00 +0100 (Wed, 17 Jan 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/04/msg00022.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");

  script_tag(name:"affected", value:"hunspell-en-us on Debian Linux");

  script_tag(name:"solution", value:"For Debian 7 'Wheezy', this problem has been fixed in version
20070829-6+deb7u1.

We recommend that you upgrade your hunspell-en-us packages.");

  script_tag(name:"summary", value:"The dictionary provided by this package had an unnecessary unversioned
conflict against the thunderbird package which recently got reintroduced
into Wheezy.

  This NVT has been deprecated as it doesn't have any security relevance.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
