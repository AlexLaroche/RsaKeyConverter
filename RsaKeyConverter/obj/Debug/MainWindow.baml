   M S B A M L   `   `   `  ����J  FRsaKeyConverter, Version=1.0.0.0, Culture=neutral, PublicKeyToken=nullE'clr-namespace:RsaKeyConverter.ViewModelRsaKeyConverter.ViewModel  5   	        RsaKeyConverter.MainWindow   5   	   \ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    5   	   R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	   5c'clr-namespace:RsaKeyConverter.ViewModel     5   	   3   -RsaKeyConverter.ViewModel.MainVindowViewModel    Instance � DataContext# Z  5   	    � Title$ RSA Key Tool��5   	   $	��550��6   $
��1200��6+   .��5      �  � ColumnDefinitions 5   
   �� 5	      $	��50* �6   6-   �� 5
      $	��50* �6   6-   �� 5      $	��50* �6   6-    � RowDefinitions 5   
   �� 5      5      �� 5      $��50 �6   5      �� 5      $��50 �6   5      .+�5   
   �� $��0��6   $��0��6"   $��Stretch=�62   $��5q�6P   $��Stretch=�6[   .+�5      �� $��
XML Format��6   $
��Bold"�6)   6=   �� 5      $��
Public Key��6   6+   �� 5      $	��100��6   $��Stretch=�6#   $��5q�6A   $	��Top=�6L    �� TextWrapping$ WrapWithOverflow=�6�   " �� VerticalScrollBarVisibility$
 Auto=�6�    �� AcceptsReturn . ��6d   �� *XmlRsaPublic+6�   �� 5      $��Private/Public Key Pair��6   68   �� 5      $	��200��6   $��Stretch=�6#   $��5q�6A   $	��Top=�6L   $ WrapWithOverflow=�6�   $
 Auto=�6�    . ��6d   �� *XmlRsaPrivate+6�   5      �� 5   
   $��0��6   $��1��6"   $��Stretch=�62   $��5q�6P   $��Stretch=�6[   .+�5      �� $��
PEM Format��6   $
��Bold"�6)   6=   �� 5      $��
Public Key��6   6+   �� 5      $	��100��6   $��Stretch=�6#   $��5q�6A   $	��Top=�6L   $ WrapWithOverflow=�6�   $
 Auto=�6�    . ��6d   �� *PemRsaPublic+6�   �� 5       $��Private/Public Key Pair��6   68   �� 5!      $	��200��6   $��Stretch=�6#   $��5q�6A   $	��Top=�6L   $ WrapWithOverflow=�6�   $
 Auto=�6�    . ��6d   �� *PemRsaPrivate+6�   5"      �� 5#   
   $��0��6   $��2��6"   $��Stretch=�62   $��5q�6P   $��Stretch=�6[   .+�5$      �� $��
DER Format��6   $
��Bold"�6)   6=   �� 5%      $��
Public Key��6   6+   �� 5&      $	��100��6   $��Stretch=�6#   $��5q�6A   $	��Top=�6L   $ WrapWithOverflow=�6�   $
 Auto=�6�    . ��6d   �� *DerRsaPublic+6�   �� 5'      $��Private/Public Key Pair��6   68   �� 5(      $	��200��6   $��Stretch=�6#   $��5q�6A   $	��Top=�6L   $ WrapWithOverflow=�6�   $
 Auto=�6�    . ��6d   �� *DerRsaPrivate+6�   5)      �� 5*   
   $��1��6   $��3��6"   $��Stretch=�66   $��5q�6T   $��Stretch=�6_    �� Orientation$ 
Horizontal=�6{   .+�5+      �� $��
Export XML��6   $��23��6*   $	��150��66   $
��Left=�6B   $��5q�6]   ��6h   �� *	ExportXml+�� 5,      $��
Export PEM��6   $��23��6*   $	��150��66   $
��Left=�6B   $��5q�6]   ��6h   �� *	ExportPem+�� 5-      $��
Export DER��6   $��23��6*   $	��150��66   $
��Left=�6B   $��5q�6]   ��6h   �� *	ExportDer+�� 5.      $��Generate New Key��6   $��23��60   $	��150��6<   $
��Left=�6H   $��5q�6c   ��6n   �� *GenerateNewKey+�� 5/      $��
Clear keys��6   $��23��6*   $	��150��66   $
��Left=�6B   $��5q�6]   ��6h   �� *	ClearKeys+50      �� 51   
   $��2��6   $��3��6"   $��Stretch=�66   $��5q�6T   $��Stretch=�6_   $ 
Horizontal=�6{   .+�52      �� $��Convert XML to PEM/DER��6   $��23��66   $	��150��6B   $
��Left=�6N   $��5q�6i   ��6t   �� *ConvertFromXmlToPemDer+�� 53      $��Convert PEM to XML/DER��6   $��23��66   $	��150��6B   $
��Left=�6N   $��5q�6i   ��6t   �� *ConvertFromPemToXmlDer+�� 54      $��Convert DER to XML/PEM��6   $��23��66   $	��150��6B   $
��Left=�6N   $��5q�6i   ��6t   �� *ConvertFromDerToXmlPem+55      56      57      