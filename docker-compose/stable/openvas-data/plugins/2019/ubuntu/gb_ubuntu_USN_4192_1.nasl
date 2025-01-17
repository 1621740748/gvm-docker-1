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
  script_oid("1.3.6.1.4.1.25623.1.0.844242");
  script_version("2019-12-12T11:35:23+0000");
  script_cve_id("CVE-2019-12974", "CVE-2019-12975", "CVE-2019-12976", "CVE-2019-12977", "CVE-2019-12978", "CVE-2019-12979", "CVE-2019-13135", "CVE-2019-13137", "CVE-2019-13295", "CVE-2019-13297", "CVE-2019-13300", "CVE-2019-13301", "CVE-2019-13304", "CVE-2019-13305", "CVE-2019-13306", "CVE-2019-13307", "CVE-2019-13308", "CVE-2019-13309", "CVE-2019-13310", "CVE-2019-13311", "CVE-2019-13391", "CVE-2019-13454", "CVE-2019-14981", "CVE-2019-15139", "CVE-2019-15140", "CVE-2019-16708", "CVE-2019-16709", "CVE-2019-16710", "CVE-2019-16711", "CVE-2019-16713");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-12-12 11:35:23 +0000 (Thu, 12 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-11-15 03:00:52 +0000 (Fri, 15 Nov 2019)");
  script_name("Ubuntu Update for imagemagick USN-4192-1");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU18\.04 LTS|UBUNTU19\.10|UBUNTU19\.04|UBUNTU16\.04 LTS)");

  script_xref(name:"USN", value:"4192-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-November/005210.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'imagemagick'
  package(s) announced via the USN-4192-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that ImageMagick incorrectly handled certain malformed
image files. If a user or automated system using ImageMagick were tricked
into opening a specially crafted image, an attacker could exploit this to
cause a denial of service or possibly execute code with the privileges of
the user invoking the program.");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Ubuntu 19.10, Ubuntu 19.04, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick", ver:"8:6.9.7.4+dfsg-16ubuntu6.8", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6.q16", ver:"8:6.9.7.4+dfsg-16ubuntu6.8", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"-6.q16-7", ver:"8:6.9.7.4+dfsg-16ubuntu6.8", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-3", ver:"8:6.9.7.4+dfsg-16ubuntu6.8", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-3-extra", ver:"8:6.9.7.4+dfsg-16ubuntu6.8", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU19.10") {

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick", ver:"8:6.9.10.23+dfsg-2.1ubuntu3.1", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6.q16", ver:"8:6.9.10.23+dfsg-2.1ubuntu3.1", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"-6.q16-8", ver:"8:6.9.10.23+dfsg-2.1ubuntu3.1", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-6", ver:"8:6.9.10.23+dfsg-2.1ubuntu3.1", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-6-extra", ver:"8:6.9.10.23+dfsg-2.1ubuntu3.1", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU19.04") {

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick", ver:"8:6.9.10.14+dfsg-7ubuntu2.3", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6.q16", ver:"8:6.9.10.14+dfsg-7ubuntu2.3", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"-6.q16-8", ver:"8:6.9.10.14+dfsg-7ubuntu2.3", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-6", ver:"8:6.9.10.14+dfsg-7ubuntu2.3", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-6-extra", ver:"8:6.9.10.14+dfsg-7ubuntu2.3", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick", ver:"8:6.8.9.9-7ubuntu5.15", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6.q16", ver:"8:6.8.9.9-7ubuntu5.15", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"-6.q16-5v5", ver:"8:6.8.9.9-7ubuntu5.15", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-2", ver:"8:6.8.9.9-7ubuntu5.15", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-2-extra", ver:"8:6.8.9.9-7ubuntu5.15", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
