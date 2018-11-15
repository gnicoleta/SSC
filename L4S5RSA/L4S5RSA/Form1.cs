using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace L4S5RSA
{
    public partial class Form1 : Form
    {

        RSACryptoServiceProvider asmAlg = new RSACryptoServiceProvider(2048);
        ConversionHandler myConv = new ConversionHandler();
        SHA256Managed myHash = new SHA256Managed();
        byte[] signature;
        byte[] plain;
        byte[] ciphertext;

        public Form1()
        {
            InitializeComponent();
        }
        //generate RSA
        private void button1_Click(object sender, EventArgs e)
        {
            int size = asmAlg.KeySize;
            //private key
            richTextBox1.Text = asmAlg.ToXmlString(true);

            //public key
            richTextBox2.Text = asmAlg.ToXmlString(false);

            System.Windows.Forms.MessageBox.Show("Private key: " + asmAlg.ToXmlString(true) + "\n" + "Public key: " + asmAlg.ToXmlString(false));

        }

        //encrypt
        private void button2_Click(object sender, EventArgs e)
        {
            ciphertext = asmAlg.Encrypt(myConv.StringToByteArray(textBox1.Text), true);
            richTextBox3.Text = myConv.ByteArrayToHexString(ciphertext);
        }

        //decrypt
        private void button3_Click(object sender, EventArgs e)
        {
            plain = asmAlg.Decrypt(myConv.HexStringToByteArray(richTextBox3.Text), true);
            textBox1.Text = myConv.ByteArrayToString(plain);
        }

        //sign
        private void button4_Click(object sender, EventArgs e)
        {
            signature = asmAlg.SignData(System.Text.Encoding.ASCII.GetBytes(textBox1.Text), myHash);
            richTextBox4.Text = myConv.ByteArrayToHexString(signature);
        }

        //verify signature
        private void button5_Click(object sender, EventArgs e)
        {
            //verified a signature on a given message
            bool verified;
            verified = asmAlg.VerifyData(System.Text.Encoding.ASCII.GetBytes(textBox1.Text), myHash, signature);

            if (verified)
            {
                System.Windows.Forms.MessageBox.Show("OK !!!");
            }
            else
            {
                System.Windows.Forms.MessageBox.Show("NOT OK !!!");
            }
        }


        class ConversionHandler
        {
            public byte[] StringToByteArray(string s)
            {
                return CharArrayToByteArray(s.ToCharArray());
            }
            public byte[] CharArrayToByteArray(char[] array)
            {
                return Encoding.ASCII.GetBytes(array, 0, array.Length);
            }
            public string ByteArrayToString(byte[] array)
            {
                return Encoding.ASCII.GetString(array);
            }
            public string ByteArrayToHexString(byte[] array)
            {
                string s = "";
                int i;
                for (i = 0; i < array.Length; i++)
                {
                    s = s + NibbleToHexString((byte)((array[i] >> 4) &
                    0x0F)) + NibbleToHexString((byte)(array[i] &
                    0x0F));
                }
                return s;
            }
            public byte[] HexStringToByteArray(string s)
            {
                byte[] array = new byte[s.Length / 2];
                char[] chararray = s.ToCharArray();
                int i;
                for (i = 0; i < s.Length / 2; i++)
                {
                    array[i] = (byte)(((HexCharToNibble(chararray[2 * i])
                    << 4) & 0xF0) | ((HexCharToNibble(chararray[2
                    * i + 1]) & 0x0F)));
                }
                return array;
            }
            public string NibbleToHexString(byte nib)
            {
                string s;
                if (nib < 10)
                {
                    s = nib.ToString();
                }
                else
                {
                    char c = (char)(nib + 55);
                    s = c.ToString();
                }
                return s;
            }
            public byte HexCharToNibble(char c)
            {
                byte value = (byte)c;
                if (value < 65)
                {
                    value = (byte)(value - 48);
                }
                else
                {
                    value = (byte)(value - 55);
                }
                return value;
            }
        }
    }
}
