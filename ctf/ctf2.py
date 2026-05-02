import cv2
import numpy as np

im1 = cv2.imread("../CTF_DATA/CTF2/Layer1.png")
im2 = cv2.imread("../CTF_DATA/CTF2/Layer2.png")

w,h,_ = im1.shape


final = im1 ^ im2


cv2.imwrite("ctf2flag.png", final) 