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

namespace L5S7DSA
{
    public partial class Form1 : Form
    {

        ConversionHandler myConv = new ConversionHandler();
        DSACryptoServiceProvider myDSA = new DSACryptoServiceProvider(512);
        byte[] sig;
        byte[] data;

        public Form1()
        {
            InitializeComponent();
        }
        
        //sign
        private void button1_Click(object sender, EventArgs e)
        {
            data = myConv.StringToByteArray(textBox1.Text);
            sig = myDSA.SignData(data);
            textBox2.Text = myConv.ByteArrayToHexString(sig);
        }

        //verify
        private void button2_Click(object sender, EventArgs e)
        {
            //verified a signature on a given message
            bool verified;
            verified = myDSA.VerifyData(data, sig);

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
