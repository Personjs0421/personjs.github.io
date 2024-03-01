---
title: liwary
date: 2024-02-29 21:45:18
tags:
---

Libwary Writeup
                
*Disclaimer: I neither did this completely on my own nor did this during the competition. Although I solved 90% on my own, I did get a pretty big hint*


RECON
========================================================
The Website
-

We are presented with a dropdown menu with 5 books. One of them is called "The flag", which obviously immediately gives us the flag and this writeup doesn't actually exist.

Moving on, we can select which book to read, and it its contents are shown on the page.

There aren't any other ways to give user inputs, and we can't modify any of the book options, so we look elsewhere. 

Checking our cookies, I noticed that we have a PHPSESSID, of course in base64.
Decrypting this, we are provided with a serialised PHP object.

`O:4:"User":1:{s:4:"name";s:12:"User86968804";}`


*Here comes me being dumb. As this was my first ever CTF competition, I had very little experience and had no clue what PHP serialisation was. So, I gave up here during the competition, after which someone told me that the solution was PHP deserialisation, and a few Google searches later, I solved it (yay).*

Deserialising the object, we get:


`__PHP_Incomplete_Class Object`
`(`
`    [__PHP_Incomplete_Class_Name] => User`
`    [name] => User86968804`
`)`

Essentially, the token is a serialized PHP object of class `User` and a value for name.

Very interesting. We may be able to exploit this in the future as the code displays "Welcome to the Libwary, {name}"


Files and source
-

We are given a file, Libwary.zip. In it we have 2 PHP files, index.php and util.php as well as a directory containing the books, fakeflag.txt and flag.txt, of course with the redacted flag.

Opening util.php, we can see the following:



![Alt text](https://github.com/Personjs0421/Personjs0421.github.io/blob/main/source/pfp.jpg)

We notice that there are two classes,  `book`  and `user`. The User class does... well not really anything. However, the book class is interesting. We can see that it uses the `$name` variable to find the corresponding book and then returns the content whenever an instance of the class is treated as a string.

Also note that if the name is not `fakeflag` but the name contains "flag", the word "flag" gets deleted.




EXPLOIT
=======
Now for the fun part, exploitation.

The Big Idea
--
The main vulnerability lies in these two lines:

`$user = unserialize(base64_decode($_COOKIE['PHPSESSID']));`
and, of course
`echo $user;`

If we can get `echo $user` to echo the contents of a Book object, we could just use that to get the contents of flag.txt. 

Very conveniently, the `__tostring()` function does exactly what we need. If we just changed the PHPSESSID cookie to a serialised object of class `Book`, like, say, I don't know, a `Book` object with the name flag.txt, it would just echo out the contents.

Execution
--

Firstly, we create a serialised object that looks like this:

`O:4:"Book":1:{s:4:"name";s:8:"flag.txt";}`

This creates an instance of `Book` that has the name "flag.txt".

Next, we encode it in Base64 to get this:

`Tzo0OiJCb29rIjoxOntzOjQ6Im5hbWUiO3M6ODoiZmxhZy50eHQiO30`

Passing this into our PHPSESSID and...

image to be added

Whoops. Forgot about the final defence code.

`//final defence`
 
` if ($this->name != "fakeflag.txt") $this->name = str_ireplace("flag", "", $this->name);`

However, this is an easy fix. We just change up our serialised object to this:
 `O:4:"Book":1:{s:4:"name";s:12:"flaflagg.txt";}` 

When the code tries to replace the "flag" in "flaflagg", it just gives us back "flag.txt"

Re-encoding and re-serialising, we get:

`Tzo0OiJCb29rIjoxOntzOjQ6Im5hbWUiO3M6MTI6ImZsZmxhZ2FnLnR4dCI7fQ`

Now we pass this into our PHPSESSID and..

image

Bam. Flag.
