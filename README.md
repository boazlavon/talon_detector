# Form Analyzer

## Introduction

Many items are sent over HTTP POST data to various targets. Malicious attackers may use XSS or malicious extensions to send sensitive form data to additional targets and steal credentials.

The target of this exercise is to create a simple detection tool which identifies possibly malicious activity in HTTP POST requests.

The solution shall receive all HTTP POST requests sent by the user and will output the list of suspicious requests, based on various rules.

For this exercise, you are required to implement the following rules:
1. two identical user/password pairs are sent within 10 seconds to different hosts
2. a password field containing a password from the list of top passwords (taken from [here](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt)) used in a secure site as listed in secure-sites.txt

## Implementation

- Your solution must be implemented in **modern** CPP (hint: think twice before using new/delete)
- Your solution must work efficiently
- Your solution must work on either Windows, Linux, or both
- Your solution may be documented as you see fit - e.g. only in non-trivial areas 
- Your solution will produce a single executable and include anything necessary to build it (e.g. make, cmake, or meson files)

## Inputs

The executable will receive 3 file paths as arguments: secure sites, password list, and the input json.

Secure sites and password lists are line separated (LF)

The solution will receive a JSON file containing the entries. Each entry will include the following fields:
  * timestamp
  * url
  * host
  * post request content, encoded in application/x-www-form-urlencoded

For example:
>     {
>       timestamp: "2014-11-12T19:12:14.505Z",
>       url: "/login",
>       host: "www.gmail.com",   
>       content: "user=root&password=qwerty&tokenid=t1a2lo3n4"
>     }

Example input files are attached along with the exercise.

## Output

The solution shall write to console regarding suspicious events, including why they were suspicious. After completely analyzing a request, a summary line shall be printed to the screen including its position in the input file, its timestamp (in textual format), and the results of the analysis: 0- OK, 1-identical passwords within 10 seconds, 2-common password, 3-both matched

A possible output may look like this:
```
Common password found: qwerty on secure host www.talon-sec.com
0)      ts: 2021-11-12T19:12:14.505Z     result: 2
Identical User/Password pair found diff under 10s: 2000ms in host www.nottalon-sec.com user/pass: root/qwerty
1)      ts: 2021-11-12T19:12:16.505Z     result: 1
2)      ts: 2021-11-12T19:12:16.506Z     result: 0
3)      ts: 2021-11-12T19:12:18.505Z     result: 0
Identical User/Password pair found diff under 10s: 3374ms in host www.nottalon-sec.com user/pass: root/qwerty
4)      ts: 2021-11-12T19:12:19.879Z     result: 1
5)      ts: 2021-11-12T19:12:20.000Z     result: 0
6)      ts: 2021-11-12T19:12:30.001Z     result: 0
Identical User/Password pair found diff under 10s: 9998ms in host www.my-web.com user/pass: admin/admin
7)      ts: 2021-11-12T19:12:39.999Z     result: 1
Identical User/Password pair found diff under 10s: 124ms in host www.not-my-web.com user/pass: admin/admin
8)      ts: 2021-11-12T19:12:40.123Z     result: 1
Identical User/Password pair found diff under 10s: 0ms in host www.talon-sec.com user/pass: admin/admin
Common password found: admin on secure host www.talon-sec.com
9)      ts: 2021-11-12T19:12:40.123Z     result: 3
```
## Assumptions

You may assume the following:
  * All username fields will be named 'user' and all password fields will be named 'password'
  * Requests may have between 0 to 1000 parameters and may not always include 'user' and 'password' parameters
  * Requests inside the input json are received in chronological order (first items in the list are the least recent)
  * Usernames and passwords are cAsE SenSiTIve
  * You are expected (and encouraged) to use 3rd party packages, e.g. jsoncpp and HowardHinnant/date

Good Luck!