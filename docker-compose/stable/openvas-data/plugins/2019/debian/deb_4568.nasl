# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.704568");
  script_version("2019-11-27T15:23:21+0000");
  script_cve_id("CVE-2019-3466");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-11-27 15:23:21 +0000 (Wed, 27 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-17 03:00:04 +0000 (Sun, 17 Nov 2019)");
  script_name("Debian Security Advisory DSA 4568-1 (postgresql-common - security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|9)");

  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4568.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4568-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql-common'
  package(s) announced via the DSA-4568-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Rich Mirch discovered that the pg_ctlcluster script didn't drop
privileges when creating socket/statistics temporary directories, which
could result in local privilege escalation.");

  script_tag(name:"affected", value:"'postgresql-common' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (stretch), this problem has been fixed
in version 181+deb9u3.

For the stable distribution (buster), this problem has been fixed in
version 200+deb10u3.

We recommend that you upgrade your postgresql-common packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
# nb: The advisory listed many more binaries, yet the only affected source package seems to be postgresql-common, as stated.
if(!isnull(res = isdpkgvuln(pkg:"postgresql-common", ver:"200+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"postgresql-common", ver:"181+deb9u3", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
