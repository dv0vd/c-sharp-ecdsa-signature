using System;
using System.IO;
using System.Security.Cryptography;
using System.Windows.Forms;

namespace lab1
{
    public partial class Form1 : Form
    {
        private const string inputSigniture = "Файл ЭЦП",inputFile = "Входной файл...", outputFile = "Каталог сохранения выходных файлов...", keysFile = "Файл с ключами...";
        private string inputFileName, outputDirectory, inputSignitureFile, inputKeysFile;

        public Form1()
        {
            InitializeComponent();
            label4.Text = inputSigniture;
        }

        // Выбор входного файла для подписи
        private void button1_Click(object sender, EventArgs e)
        {
            OpenFileDialog OPF = new OpenFileDialog();
            OPF.Filter = "Файлы |*";
            OPF.Title = "Выбрать файл";
            if (OPF.ShowDialog() == DialogResult.OK)
            {
                inputFileName = OPF.FileName;
                label1.Text = inputFileName;
            }
        }

        private void Finish()
        {
            label1.Text = inputFile;
            label2.Text = outputFile;
            label4.Text = inputSigniture;
            label3.Text = keysFile;
        }

        // Выбор файла с ключами
        private void button6_Click(object sender, EventArgs e)
        {
            OpenFileDialog OPF = new OpenFileDialog();
            OPF.Filter = "Файлы |*";
            OPF.Title = "Выбрать файл";
            if (OPF.ShowDialog() == DialogResult.OK)
            {
                inputKeysFile = OPF.FileName;
                label3.Text = inputKeysFile;
            }
        }

        // Создание ключей
        private static ECDsaCng CreateECDKey(out byte[] PrivateKey, out byte[] PublicKey, string KeyName = "Ключ шифрования", string keyAlias = "AdminKey")
        {
            var p = new CngKeyCreationParameters
            {
                ExportPolicy = CngExportPolicies.AllowPlaintextExport,
                KeyCreationOptions = CngKeyCreationOptions.OverwriteExistingKey,
                UIPolicy = new CngUIPolicy(CngUIProtectionLevels.ProtectKey, KeyName, null, null, null)
            };
            var key = CngKey.Create(CngAlgorithm.ECDsaP256, keyAlias, p);
            using (ECDsaCng dsa = new ECDsaCng(key))
            {
                dsa.HashAlgorithm = CngAlgorithm.Sha256;
                PublicKey = dsa.Key.Export(CngKeyBlobFormat.EccPublicBlob);
                PrivateKey = dsa.Key.Export(CngKeyBlobFormat.EccPrivateBlob);
                return dsa;
            }
        }

        // Начало процесса подписи
        private void button3_Click(object sender, EventArgs ee)
        {
            if ((label1.Text == inputFile) || (label2.Text == outputFile))  //проверка выбора файлов
            {
                MessageBox.Show("Не выбраны пути к файлам!");
            }
            else
            {
                byte[] private_key, public_key;
                ECDsaCng dsa = CreateECDKey(out private_key, out public_key);
                dsa.HashAlgorithm = CngAlgorithm.Sha256;
                FileStream fstream = new FileStream(inputFileName, FileMode.Open);
                byte[] data = new byte[fstream.Length];
                fstream.Read(data, 0, data.Length);
                ECDsaCng ecsdKey = new ECDsaCng(CngKey.Import(private_key, CngKeyBlobFormat.EccPrivateBlob));
                byte[] signature = ecsdKey.SignData(data);
                string path = outputDirectory + "\\ЭЦП";
                FileStream foutstream = new FileStream(path, FileMode.Create);
                foutstream.Write(signature, 0, signature.Length);
                path = outputDirectory + "\\ЭЦП_ключи.txt";
                File.WriteAllBytes(outputDirectory + "\\ЭЦП_ключи.txt", public_key);
                fstream.Close();
                foutstream.Close();
                MessageBox.Show("Успех!");
                Finish();
            }
        }

        // Выбор директории сохранения ЭЦП
        private void button2_Click(object sender, EventArgs e)
        {
            FolderBrowserDialog FBD = new FolderBrowserDialog();
            if (FBD.ShowDialog() == DialogResult.OK)
            {
                outputDirectory = FBD.SelectedPath;
                FBD.Description = "Выбрать директорию";
                label2.Text = outputDirectory;
            }
        }

        // Выбор файла ЭЦП
        private void button5_Click(object sender, EventArgs e)
        {
            OpenFileDialog OPF = new OpenFileDialog();
            OPF.Filter = "Файлы |*";
            OPF.Title = "Выбрать файл";
            if (OPF.ShowDialog() == DialogResult.OK)
            {
                inputSignitureFile = OPF.FileName;
                label4.Text = inputSignitureFile;
            }
        }

        // Начало проверки подписи
        private void button4_Click(object sender, EventArgs ee)
        {
            if ((label1.Text == inputFile) || (label4.Text == inputSigniture) || (label3.Text == keysFile))  //проверка выбора файлов
            {
                MessageBox.Show("Не выбраны пути к файлам!");
            }
            else
            {
                FileStream fstreamBasicFile = new FileStream(inputFileName, FileMode.Open);
                byte[] data = new byte[fstreamBasicFile.Length];
                fstreamBasicFile.Read(data,0, data.Length);
                byte[] signature = File.ReadAllBytes(inputSignitureFile);
                fstreamBasicFile.Close();
                var publickey = File.ReadAllBytes(inputKeysFile);
                ECDsaCng ecsdKeyVerify;
                try
                {
                    ecsdKeyVerify = new ECDsaCng(CngKey.Import(publickey, CngKeyBlobFormat.EccPublicBlob));

                }
                catch
                {
                    MessageBox.Show("Цифровая подпись не совпадает!");
                    Finish();

                    return;
                }
                ecsdKeyVerify.HashAlgorithm = CngAlgorithm.Sha256;
                if (ecsdKeyVerify.VerifyData(data, signature))
                {
                    MessageBox.Show("Цифровая подпись совпадает!");
                }
                else
                {
                    MessageBox.Show("Цифровая подпись не совпадает!");

                }
                Finish();
            }
        }
    }
}
