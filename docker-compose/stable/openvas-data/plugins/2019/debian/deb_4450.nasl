# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.704450");
  script_version("2020-06-09T14:44:58+0000");
  script_cve_id("CVE-2019-11555");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-06-09 14:44:58 +0000 (Tue, 09 Jun 2020)");
  script_tag(name:"creation_date", value:"2019-05-25 02:00:04 +0000 (Sat, 25 May 2019)");
  script_name("Debian Security Advisory DSA 4450-1 (wpa - security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4450.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4450-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wpa'
  package(s) announced via the DSA-4450-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in the WPA protocol implementation found in
wpa_supplication (station) and hostapd (access point).

The EAP-pwd implementation in hostapd (EAP server) and wpa_supplicant (EAP
peer) doesn't properly validate fragmentation reassembly state when receiving
an unexpected fragment. This could lead to a process crash due to a NULL
pointer dereference.

An attacker in radio range of a station or access point with EAP-pwd support
could cause a crash of the relevant process (wpa_supplicant or hostapd),
ensuring a denial of service.");

  script_tag(name:"affected", value:"'wpa' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (stretch), this problem has been fixed in
version 2:2.4-1+deb9u4.

We recommend that you upgrade your wpa packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"hostapd", ver:"2:2.4-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wpagui", ver:"2:2.4-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wpasupplicant", ver:"2:2.4-1+deb9u4", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
