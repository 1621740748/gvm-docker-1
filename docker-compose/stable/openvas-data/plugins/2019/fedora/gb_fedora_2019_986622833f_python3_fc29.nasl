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
  script_oid("1.3.6.1.4.1.25623.1.0.876955");
  script_version("2019-11-04T08:05:52+0000");
  script_cve_id("CVE-2019-16056", "CVE-2019-9636", "CVE-2019-5010");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-11-04 08:05:52 +0000 (Mon, 04 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-02 03:33:10 +0000 (Sat, 02 Nov 2019)");
  script_name("Fedora Update for python3 FEDORA-2019-986622833f");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC29");

  script_xref(name:"FEDORA", value:"2019-986622833f");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/QASRD4E2G65GGEHYKVHYCXB2XWAGTNL4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3'
  package(s) announced via the FEDORA-2019-986622833f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Python is an accessible, high-level, dynamically typed, interpreted programming
language, designed with an emphasis on code readability.
It includes an extensive standard library, and has a vast ecosystem of
third-party libraries.

The python3 package provides the 'python3' executable: the reference
interpreter for the Python language, version 3.
The majority of its standard library is provided in the python3-libs package,
which should be installed automatically along with python3.
The remaining parts of the Python standard library are broken out into the
python3-tkinter and python3-test packages, which may need to be installed
separately.

Documentation for Python is provided in the python3-docs package.

Packages containing additional libraries for Python are generally named with
the 'python3-' prefix.");

  script_tag(name:"affected", value:"'python3' package(s) on Fedora 29.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC29") {

  if(!isnull(res = isrpmvuln(pkg:"python3", rpm:"python3~3.7.5~1.fc29", rls:"FC29"))) {
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